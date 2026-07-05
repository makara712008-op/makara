"""
Reach Flower Boutique — backend
Handles: order intake -> KHPAY ABA PayWay QR generation -> webhook confirmation -> Telegram notification

SETUP:
  pip install flask requests python-dotenv
  Create a .env file (see .env.example) with your real secrets. NEVER commit it or paste it in chat.
  For local testing, KHPAY needs to reach your callback_url publicly — use a tunnel, e.g.:
      ngrok http 5000
  Then set BASE_URL to the ngrok https URL.

RUN:
  python app.py
"""

import hashlib
import hmac
import os
import time
import uuid
from functools import wraps

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template, abort

load_dotenv()

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config — all secrets come from environment variables, never hardcoded.
# ---------------------------------------------------------------------------
KHPAY_API_KEY = os.environ["KHPAY_API_KEY"]              # required
KHPAY_WEBHOOK_SECRET = os.environ["KHPAY_WEBHOOK_SECRET"]  # required, set in KHPAY dashboard
TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]      # required
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]          # required
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")  # public URL, e.g. your ngrok/domain
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")  # optional but strongly recommended for /admin

KHPAY_BASE = "https://khpay.site/api/v1"
KHPAY_HEADERS = {
    "Authorization": f"Bearer {KHPAY_API_KEY}",
    "Content-Type": "application/json",
}

# ---------------------------------------------------------------------------
# In-memory order store. Swap for a real DB (sqlite/postgres) in production —
# this dict is wiped every time the process restarts.
# ---------------------------------------------------------------------------
# order_id -> {items, delivery, total, status, transaction_id}
ORDERS = {}
# transaction_id -> order_id  (fast lookup for webhook)
TX_TO_ORDER = {}


def compute_total(items):
    return round(sum(item["price"] * item["quantity"] for item in items), 2)


def send_telegram_message(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    resp = requests.post(
        url,
        json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
        timeout=10,
    )
    if not resp.ok:
        app.logger.error("Telegram send failed: %s", resp.text)
    return resp.ok


def build_order_message(order_id, order):
    lines = [f"🌸 <b>New Paid Order #{order_id}</b>", ""]
    for item in order["items"]:
        lines.append(f"• {item['name']} x{item['quantity']} — ${item['price'] * item['quantity']:.2f}")
    lines.append("")
    lines.append(f"<b>Total: ${order['total']:.2f}</b>")
    lines.append("")
    d = order["delivery"]
    lines.append(f"👤 {d['name']}")
    lines.append(f"📍 {d['address']}")
    lines.append(f"📅 {d['date']}")
    if d.get("note"):
        lines.append(f"📝 {d['note']}")
    lines.append("")
    lines.append(f"txn: {order.get('transaction_id', '-')}")
    return "\n".join(lines)


def require_admin(view):
    """Very basic shared-secret gate for /admin routes.

    Set ADMIN_TOKEN in .env and visit /admin?token=... (or send it as the
    X-Admin-Token header). Without ADMIN_TOKEN set, /admin is wide open —
    fine for local testing, NOT fine for a public deployment.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if ADMIN_TOKEN:
            supplied = request.args.get("token") or request.headers.get("X-Admin-Token")
            if not supplied or not hmac.compare_digest(supplied, ADMIN_TOKEN):
                abort(401)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# 0. Storefront + admin dashboard pages.
# ---------------------------------------------------------------------------
@app.route("/")
def storefront():
    return render_template("index.html")


@app.route("/admin")
@require_admin
def admin_dashboard():
    return render_template("admin.html")


@app.route("/admin/api/orders")
@require_admin
def admin_orders_api():
    # Newest first.
    rows = sorted(
        ({"order_id": oid, **o} for oid, o in ORDERS.items()),
        key=lambda o: o["created_at"],
        reverse=True,
    )
    return jsonify(rows)


# ---------------------------------------------------------------------------
# 1. Customer submits cart + delivery form -> create pending order,
#    ask KHPAY for a QR, return payment_url to redirect the browser to.
# ---------------------------------------------------------------------------
@app.route("/place-order", methods=["POST"])
def place_order():
    data = request.get_json(force=True, silent=True) or {}
    items = data.get("items")
    delivery = data.get("delivery")

    if not items:
        return jsonify({"message": "Cart is empty."}), 400
    required_fields = ("name", "address", "date")
    if not delivery or not all(delivery.get(f) for f in required_fields):
        return jsonify({"message": "Missing delivery details."}), 400

    total = compute_total(items)
    if total <= 0:
        return jsonify({"message": "Invalid order total."}), 400

    order_id = uuid.uuid4().hex[:8]
    ORDERS[order_id] = {
        "items": items,
        "delivery": delivery,
        "total": total,
        "status": "pending_payment",
        "created_at": time.time(),
    }

    payload = {
        "amount": total,
        "currency": "USD",
        "note": f"Order #{order_id}",
        "success_url": f"{BASE_URL}/success?order_id={order_id}",
        "cancel_url": f"{BASE_URL}/cancel?order_id={order_id}",
        "callback_url": f"{BASE_URL}/webhook/khpay",
        "metadata": {"order_id": order_id},
    }

    try:
        resp = requests.post(f"{KHPAY_BASE}/qr/generate", json=payload, headers=KHPAY_HEADERS, timeout=15)
    except requests.RequestException as e:
        app.logger.error("KHPAY request failed: %s", e)
        return jsonify({"message": "Payment provider unreachable. Try again shortly."}), 502

    if resp.status_code != 201:
        app.logger.error("KHPAY error: %s", resp.text)
        try:
            err = resp.json()
        except ValueError:
            err = {}
        return jsonify({"message": err.get("error", "Failed to create payment.")}), 502

    qr_data = resp.json()
    transaction_id = qr_data["transaction_id"]

    ORDERS[order_id]["transaction_id"] = transaction_id
    TX_TO_ORDER[transaction_id] = order_id

    return jsonify({
        "payment_url": qr_data["payment_url"],
        "transaction_id": transaction_id,
        "order_id": order_id,
    }), 201


# ---------------------------------------------------------------------------
# 2. KHPAY calls this when the payment status changes.
#    Verify the HMAC signature before trusting anything in the body.
# ---------------------------------------------------------------------------
@app.route("/webhook/khpay", methods=["POST"])
def khpay_webhook():
    raw_body = request.get_data()  # raw bytes, required for correct HMAC verification
    signature = request.headers.get("X-KHPAY-Signature", "")

    expected = hmac.new(KHPAY_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        app.logger.warning("Invalid KHPAY webhook signature")
        return jsonify({"message": "invalid signature"}), 401

    event = request.get_json(force=True, silent=True) or {}

    if event.get("event") == "payment.paid":
        transaction_id = event.get("transaction_id")
        metadata = event.get("metadata") or {}
        order_id = metadata.get("order_id") or TX_TO_ORDER.get(transaction_id)

        order = ORDERS.get(order_id)
        if order and order["status"] != "paid":
            order["status"] = "paid"
            order["paid_at"] = event.get("paid_at")
            send_telegram_message(build_order_message(order_id, order))
        elif not order:
            app.logger.warning("Webhook for unknown order, txn=%s", transaction_id)

    # Always 200 quickly so KHPAY doesn't retry unnecessarily.
    return jsonify({"received": True}), 200


# ---------------------------------------------------------------------------
# 3. Customer lands here after paying. Double-check status server-side
#    (never trust the URL query string alone).
# ---------------------------------------------------------------------------
@app.route("/success")
def success():
    order_id = request.args.get("order_id")
    order = ORDERS.get(order_id)

    if not order or not order.get("transaction_id"):
        return render_template("cancel.html", message="We couldn't find that order."), 404

    try:
        resp = requests.get(
            f"{KHPAY_BASE}/qr/check/{order['transaction_id']}",
            headers=KHPAY_HEADERS,
            timeout=15,
        )
        check = resp.json() if resp.ok else {}
    except requests.RequestException:
        check = {}

    is_paid = check.get("paid") or order["status"] == "paid"

    if not is_paid:
        return render_template("cancel.html", message="Payment not confirmed yet. If you already paid, give it a few seconds and refresh."), 200

    return render_template("success.html", order_id=order_id, order=order)


@app.route("/cancel")
def cancel():
    order_id = request.args.get("order_id")
    return render_template("cancel.html", message="Payment was cancelled.", order_id=order_id)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
