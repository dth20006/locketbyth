import sys
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import os
import re
import json
import time
import uuid
import queue
import threading
import random
from datetime import datetime
from functools import wraps
from urllib.parse import quote

import dotenv
import requests
from flask import Flask, render_template, request, jsonify, send_from_directory

from locket_api import LocketAPI, LocketAPIError, test_restore_token, safe_print
from config_manager import config_manager, parse_raw_token_request, get_token_summary, decode_jwt_payload

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
dotenv.load_dotenv()

# Standalone API instance (no dependency on expired Firebase Auth)
api = LocketAPI()

subscription_ids = [
    "locket_1600_1y",
    "locket_199_1m",
    "locket_199_1m_only",
    "locket_3600_1y",
    "locket_399_1m_only",
]


# ==============================================================================
# --- Queue Management System ---
# ==============================================================================

class QueueManager:
    def __init__(self):
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.client_requests = {}
        self.processing_times = []
        self.current_processing = None
        self.recent_history = []
        self.is_vercel = os.environ.get("VERCEL") == "1"
        if not self.is_vercel:
            self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
            self.worker_thread.start()
            safe_print("[QueueManager] Worker thread started successfully.")
        else:
            safe_print("[QueueManager] Running on Vercel Serverless (synchronous queue mode).")

    def _save_vercel_requests(self):
        try:
            reqs_file = "/tmp/vercel_client_requests.json"
            serializable = {}
            for cid, r in self.client_requests.items():
                copy_r = r.copy()
                for k in ["added_at", "started_at", "completed_at"]:
                    if copy_r.get(k) and isinstance(copy_r[k], datetime):
                        copy_r[k] = copy_r[k].isoformat()
                serializable[cid] = copy_r
            with open(reqs_file, "w", encoding="utf-8") as f:
                json.dump(serializable, f)
        except Exception:
            pass

    def _load_vercel_requests(self):
        try:
            reqs_file = "/tmp/vercel_client_requests.json"
            if os.path.exists(reqs_file):
                with open(reqs_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for cid, r in data.items():
                        if cid not in self.client_requests:
                            self.client_requests[cid] = r
        except Exception:
            pass

    def add_to_queue(self, username, package_type="with_dns"):
        client_id = str(uuid.uuid4())
        request_data = {
            "username": username,
            "package_type": package_type,
            "status": "waiting",
            "result": None,
            "error": None,
            "added_at": datetime.now(),
            "started_at": None,
            "completed_at": None,
        }

        with self.lock:
            self.client_requests[client_id] = request_data

        if self.is_vercel:
            # Process synchronously immediately on Vercel so result is ready when frontend polls
            with self.lock:
                self.client_requests[client_id]["status"] = "processing"
                self.client_requests[client_id]["started_at"] = datetime.now()
            self._process_request(client_id)
            with self.lock:
                self.client_requests[client_id]["completed_at"] = datetime.now()
            self._save_vercel_requests()
        else:
            self.queue.put(client_id)
            safe_print(f"[QueueManager] Đã thêm @{username} (gói: {package_type}) vào hàng đợi. Client ID: {client_id}")
        return client_id

    def get_status(self, client_id):
        if self.is_vercel:
            self._load_vercel_requests()

        with self.lock:
            if client_id not in self.client_requests:
                return None

            request_data = self.client_requests[client_id].copy()
            position = self._get_position(client_id)
            total_queue = self.queue.qsize()
            if self.current_processing and self.current_processing != client_id:
                total_queue += 1

            estimated_time = self._estimate_wait_time(position)

            return {
                "client_id": client_id,
                "package_type": request_data.get("package_type", "with_dns"),
                "status": request_data["status"],
                "position": position,
                "total_queue": total_queue,
                "estimated_time": estimated_time,
                "result": request_data["result"],
                "error": request_data["error"],
            }

    def _get_position(self, client_id):
        if self.current_processing == client_id:
            return 0

        queue_list = list(self.queue.queue)
        if client_id in queue_list:
            return queue_list.index(client_id) + 1

        if client_id in self.client_requests:
            status = self.client_requests[client_id]["status"]
            if status in ["completed", "error"]:
                return 0

        return 0

    def _estimate_wait_time(self, position):
        if position == 0:
            return 0
        avg_time = 4
        if self.processing_times:
            avg_time = sum(self.processing_times[-10:]) / len(self.processing_times[-10:])
        return int(position * avg_time)

    def _process_queue(self):
        while True:
            try:
                client_id = self.queue.get(timeout=1)

                with self.lock:
                    if client_id not in self.client_requests:
                        continue
                    self.current_processing = client_id
                    self.client_requests[client_id]["status"] = "processing"
                    self.client_requests[client_id]["started_at"] = datetime.now()

                safe_print(f"[QueueManager] Bắt đầu xử lý cho client_id: {client_id}")
                self._process_request(client_id)

                with self.lock:
                    self.current_processing = None
                    if client_id in self.client_requests:
                        self.client_requests[client_id]["completed_at"] = datetime.now()
                        started = self.client_requests[client_id]["started_at"]
                        completed = self.client_requests[client_id]["completed_at"]
                        duration = (completed - started).total_seconds()
                        self.processing_times.append(duration)
                        if len(self.processing_times) > 20:
                            self.processing_times.pop(0)

                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                safe_print(f"[QueueManager] Lỗi worker: {e}")
                with self.lock:
                    self.current_processing = None

    def _process_request(self, client_id):
        try:
            with self.lock:
                username = self.client_requests[client_id]["username"]
                package_type = self.client_requests[client_id].get("package_type", "with_dns")

            safe_print(f"[QueueManager] Đang tìm UID cho @{username}...")
            uid_target = api.resolve_uid(username)
            if not uid_target:
                raise Exception(f"Không tìm thấy tài khoản Locket '{username}'. Vui lòng kiểm tra lại username.")

            safe_print(f"[QueueManager] Tìm thấy UID: {uid_target}. Tiến hành khôi phục Gold...")
            restore_result = api.restorePurchase(uid_target)

            product_id = restore_result.get("product_identifier") or "locket_199_1m"
            is_active = restore_result.get("is_active", True)
            expires_date = restore_result.get("expires_date")
            token_name = restore_result.get("token_name", "N/A")
            mode = restore_result.get("mode", "Standard")

            safe_print(
                f"[QueueManager] Khôi phục thành công Gold cho @{username} "
                f"(Gói: {product_id}, Token: {token_name}, Mode: {mode}, Hạn: {expires_date or 'N/A'})"
            )

            send_telegram_notification(
                username,
                uid_target,
                product_id,
                restore_result.get("raw", {}),
                package_type,
            )

            with self.lock:
                self.client_requests[client_id]["status"] = "completed"
                self.client_requests[client_id]["result"] = {
                    "success": True,
                    "username": username,
                    "uid": uid_target,
                    "package_type": package_type,
                    "has_dns": package_type == "with_dns",
                    "product_identifier": product_id,
                    "is_active": is_active,
                    "expires_date": expires_date,
                    "msg": f"Khôi phục gói {product_id} cho @{username} thành công!",
                }
                self.recent_history.insert(0, {
                    "id": client_id[:8],
                    "client_id": client_id,
                    "username": username,
                    "package_type": package_type,
                    "status": "completed",
                    "timestamp": datetime.now().strftime("%H:%M:%S %d/%m"),
                    "error": None
                })
                self.recent_history = self.recent_history[:50]

        except Exception as e:
            safe_print(f"[QueueManager] Xử lý thất bại cho {client_id}: {e}")
            with self.lock:
                self.client_requests[client_id]["status"] = "error"
                self.client_requests[client_id]["error"] = str(e)
                self.recent_history.insert(0, {
                    "id": client_id[:8],
                    "username": username if "username" in locals() else "Unknown",
                    "package_type": package_type if "package_type" in locals() else "with_dns",
                    "status": "error",
                    "timestamp": datetime.now().strftime("%H:%M:%S %d/%m"),
                    "error": str(e)
                })
                self.recent_history = self.recent_history[:50]

    def get_stats(self):
        with self.lock:
            return {
                "queue_size": self.queue.qsize(),
                "is_processing": self.current_processing is not None,
                "current_processing": self.current_processing,
                "total_requests": len(self.client_requests),
                "recent_history": self.recent_history[:25]
            }


queue_manager = QueueManager()


def send_telegram_notification(username, uid, product_id, raw_json, package_type="with_dns"):
    tg_conf = config_manager.get_telegram_config()
    bot_token = tg_conf.get("bot_token") or os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = tg_conf.get("chat_id") or os.getenv("TELEGRAM_CHAT_ID")

    if not bot_token or not chat_id:
        return

    subscription_info = json.dumps(
        raw_json.get("subscriber", {}).get("entitlements", {}).get("Gold", {}), indent=2
    )

    pkg = config_manager.get_payment_config()["packages"].get(package_type, {})
    pkg_name = f"{pkg.get('name', 'Giữ Gold')} ({pkg.get('price_formatted', '30.000đ')})"

    message = (
        f"✅ <b>Locket Gold Unlocked!</b>\n\n"
        f"👤 <b>User:</b> @{username} (<code>{uid}</code>)\n"
        f"📦 <b>Gói nạp:</b> {pkg_name}\n"
        f"⏰ <b>Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"<b>Subscription Info:</b>\n<pre>{subscription_info}</pre>"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}

    try:
        requests.post(url, json=payload, timeout=8)
    except Exception as e:
        safe_print(f"[Telegram] Gửi thông báo thất bại: {e}")


# --- Admin Authentication Decorator ---
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token_val = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
        if not token_val or not config_manager.verify_password(token_val):
            return jsonify({"success": False, "msg": "Phiên đăng nhập Admin không hợp lệ hoặc đã hết hạn."}), 401
        return f(*args, **kwargs)
    return decorated


# ==============================================================================
# --- User Routes ---
# ==============================================================================

@app.route("/health")
@app.route("/ping")
def health_check():
    return jsonify({"status": "ok", "service": "UpLocket"}), 200


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin")
def admin_page():
    return render_template("admin.html")


@app.route("/download-config")
def download_config():
    """Serves the signed iOS DNS configuration profile (.mobileconfig).
    Requires a valid client_id for with_dns package or admin credentials.
    """
    cid = request.args.get("cid", "").strip()
    token = request.args.get("token", "").strip() or request.headers.get("Authorization", "").replace("Bearer ", "").strip()

    # 1. Allow authenticated Admin
    if token and config_manager.verify_password(token):
        return send_from_directory(
            "static", "locket.mobileconfig", as_attachment=True, mimetype="application/x-apple-aspen-config"
        )

    # 2. Check Customer Client ID
    if cid:
        if queue_manager.is_vercel:
            queue_manager._load_vercel_requests()
        req = None
        with queue_manager.lock:
            req = queue_manager.client_requests.get(cid)
            if not req:
                for h in queue_manager.recent_history:
                    if h.get("client_id") == cid or (h.get("id") and cid.startswith(h.get("id"))):
                        req = h
                        break

        if req:
            package_type = req.get("package_type")
            if package_type != "with_dns":
                return (
                    "<!DOCTYPE html><html lang='vi'><head><meta charset='utf-8'><title>403 Từ Chối</title>"
                    "<style>body{background:#0b0f19;color:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}"
                    ".box{background:#111827;border:1px solid #ef4444;border-radius:16px;padding:32px;max-width:440px;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,0.5);}"
                    "h2{color:#f87171;margin-top:0;}p{color:#9ca3af;font-size:14px;line-height:1.6;}"
                    "a{color:#fbbf24;text-decoration:none;font-weight:bold;}</style></head><body>"
                    "<div class='box'><h2>🛡️ Không Thể Tải Cấu Hình DNS</h2>"
                    "<p>Đơn hàng của bạn đăng ký gói <b>Không Giữ Gold (10.000đ)</b>, không bao gồm Cấu hình DNS chống thu hồi.</p>"
                    "<p>Nếu bạn muốn giữ Gold vĩnh viễn không bị quét, vui lòng nâng cấp gói <b>Có Giữ Gold</b>.</p>"
                    "<p><a href='/'>← Quay lại trang chủ</a></p></div></body></html>",
                    403,
                )
            return send_from_directory(
                "static", "locket.mobileconfig", as_attachment=True, mimetype="application/x-apple-aspen-config"
            )

        return (
            "<!DOCTYPE html><html lang='vi'><head><meta charset='utf-8'><title>404 Hết Hạn</title>"
            "<style>body{background:#0b0f19;color:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}"
            ".box{background:#111827;border:1px solid #374151;border-radius:16px;padding:32px;max-width:440px;text-align:center;}"
            "h2{color:#9ca3af;margin-top:0;}p{color:#6b7280;font-size:14px;line-height:1.6;}"
            "a{color:#fbbf24;text-decoration:none;font-weight:bold;}</style></head><body>"
            "<div class='box'><h2>⚠️ Đơn Hàng Hết Hạn Hoặc Không Hợp Lệ</h2>"
            "<p>Không tìm thấy phiên giao dịch tương ứng trên hệ thống.</p>"
            "<p><a href='/'>← Quay lại trang chủ</a></p></div></body></html>",
            404,
        )

    # 3. No cid and not admin
    return (
        "<!DOCTYPE html><html lang='vi'><head><meta charset='utf-8'><title>403 Từ Chối</title>"
        "<style>body{background:#0b0f19;color:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}"
        ".box{background:#111827;border:1px solid #ef4444;border-radius:16px;padding:32px;max-width:440px;text-align:center;}"
        "h2{color:#f87171;margin-top:0;}p{color:#9ca3af;font-size:14px;line-height:1.6;}"
        "a{color:#fbbf24;text-decoration:none;font-weight:bold;}</style></head><body>"
        "<div class='box'><h2>🔒 Yêu Cầu Mã Giao Dịch</h2>"
        "<p>Hồ sơ DNS chỉ được cung cấp cho các đơn hàng kích hoạt gói Có Giữ Gold.</p>"
        "<p><a href='/'>← Quay lại trang chủ</a></p></div></body></html>",
        403,
    )



@app.route("/api/payment-info", methods=["GET"])
def get_payment_info():
    return jsonify({"success": True, "data": config_manager.get_payment_config()})


@app.route("/api/locket/status", methods=["GET"])
def get_locket_account_status():
    tokens = config_manager.get_api_tokens()
    has_bearer = bool(tokens.get("locket_bearer"))
    has_refresh = bool(tokens.get("locket_refresh_token"))
    email = tokens.get("locket_account_email") or ""
    name = tokens.get("locket_account_name") or ""
    uid = tokens.get("locket_account_uid") or ""

    if has_bearer and not email:
        try:
            bearer = tokens.get("locket_bearer", "")
            raw_jwt = bearer.replace("Bearer ", "").strip()
            decoded = decode_jwt_payload(raw_jwt)
            email = decoded.get("email") or ""
            name = decoded.get("name") or name
            uid = decoded.get("user_id") or decoded.get("sub") or uid
        except Exception:
            pass

    return jsonify({
        "success": True,
        "connected": has_bearer,
        "email": email,
        "name": name,
        "uid": uid,
        "has_refresh": has_refresh
    })


@app.route("/api/locket/connect", methods=["POST"])
def connect_locket_account():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    pwd = (data.get("password") or "").strip()
    raw_text = (data.get("raw_text") or "").strip()

    # 1. Login with email & password
    if email and pwd:
        try:
            url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=AIzaSyCQngaaXQIfJaH0aS2l7REgIjD7nL431So"
            headers = {
                "X-Ios-Bundle-Identifier": "com.locket.Locket",
                "User-Agent": "Locket/2283 CFNetwork/3896.100.1.2.1 Darwin/27.0.0",
                "Content-Type": "application/json"
            }
            payload = {
                "email": email,
                "password": pwd,
                "clientType": "CLIENT_TYPE_IOS",
                "returnSecureToken": True
            }
            res = requests.post(url, headers=headers, json=payload, timeout=10)
            res_data = res.json()
            if not res.ok:
                err_code = res_data.get("error", {}).get("message", "Đăng nhập thất bại")
                trans = {
                    "EMAIL_NOT_FOUND": "Email này chưa được đăng ký tài khoản Locket.",
                    "INVALID_PASSWORD": "Mật khẩu tài khoản Locket không chính xác.",
                    "USER_DISABLED": "Tài khoản Locket đã bị vô hiệu hóa.",
                }
                msg = trans.get(err_code, f"Lỗi từ Locket: {err_code}")
                return jsonify({"success": False, "msg": msg}), 400

            id_token = res_data.get("idToken")
            refresh_token = res_data.get("refreshToken")
            display_name = res_data.get("displayName") or ""
            uid = res_data.get("localId") or ""

            config_manager.set_locket_bearer(id_token)
            if refresh_token:
                config_manager.set_locket_refresh_token(refresh_token)

            tokens = config_manager.get_data().setdefault("api_tokens", {})
            tokens["locket_account_email"] = email
            tokens["locket_account_name"] = display_name
            tokens["locket_account_uid"] = uid
            config_manager.save()

            return jsonify({
                "success": True,
                "msg": f"Đăng nhập Locket thành công! Đã kết nối tài khoản {display_name or email}.",
                "account": {
                    "email": email,
                    "name": display_name,
                    "uid": uid
                }
            })
        except Exception as e:
            return jsonify({"success": False, "msg": f"Lỗi kết nối: {str(e)}"}), 500

    # 2. Raw packet / Bearer token import
    elif raw_text:
        auth_match = re.search(r"authorization:\s*(Bearer\s+[A-Za-z0-9_\-\.]+)", raw_text, re.IGNORECASE)
        appcheck_match = re.search(r"x-firebase-appcheck:\s*([A-Za-z0-9_\-\.]+)", raw_text, re.IGNORECASE)
        iid_match = re.search(r"firebase-instance-id-token:\s*([^\s\r\n]+)", raw_text, re.IGNORECASE)

        bearer_token = auth_match.group(1).strip() if auth_match else ""
        if not bearer_token:
            jwt_match = re.search(r"(Bearer\s+eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", raw_text)
            if jwt_match:
                bearer_token = jwt_match.group(1).strip()
            elif raw_text.startswith("Bearer "):
                bearer_token = raw_text
            elif raw_text.startswith("eyJ"):
                bearer_token = f"Bearer {raw_text}"

        appcheck = appcheck_match.group(1).strip() if appcheck_match else ""
        extracted_iid = iid_match.group(1).strip() if iid_match else ""

        if not bearer_token and not appcheck:
            return jsonify({"success": False, "msg": "Không tìm thấy mã Authorization hoặc AppCheck trong nội dung."}), 400

        if bearer_token:
            config_manager.set_locket_bearer(bearer_token)
        if appcheck:
            config_manager.set_firebase_appcheck(appcheck)
        if extracted_iid:
            config_manager.set_firebase_instance_id_token(extracted_iid)

        email = ""
        name = ""
        uid = ""
        try:
            raw_jwt = bearer_token.replace("Bearer ", "").strip()
            decoded = decode_jwt_payload(raw_jwt)
            email = decoded.get("email") or ""
            name = decoded.get("name") or ""
            uid = decoded.get("user_id") or decoded.get("sub") or ""
            tokens = config_manager.get_data().setdefault("api_tokens", {})
            tokens["locket_account_email"] = email
            tokens["locket_account_name"] = name
            tokens["locket_account_uid"] = uid
            config_manager.save()
        except Exception:
            pass

        return jsonify({
            "success": True,
            "msg": f"Đã lưu Token Locket thành công! (Tài khoản: {name or email or 'Locket User'})",
            "account": {
                "email": email,
                "name": name,
                "uid": uid
            }
        })

    return jsonify({"success": False, "msg": "Vui lòng nhập Email & Mật khẩu hoặc dán Token Locket."}), 400


@app.route("/api/get-user-info", methods=["POST"])
def get_user_info():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"success": False, "msg": "Dữ liệu yêu cầu không hợp lệ."}), 400

    username = (data.get("username") or "").strip().lstrip("@")
    if not username:
        return jsonify({"success": False, "msg": "Vui lòng nhập username Locket."}), 400

    try:
        profile = api.get_full_profile(username)
        if not profile or not profile.get("uid"):
            return jsonify({"success": False, "msg": f"Không tìm thấy người dùng @{username}."}), 404

        return jsonify({"success": True, "data": profile})
    except Exception as e:
        safe_print(f"[get_user_info] Error: {e}")
        return jsonify({"success": False, "msg": f"Lỗi tìm kiếm: {str(e)}"}), 500


# ==============================================================================
# --- Order & Auto Payment Management System (thueapibank.vn) ---
# ==============================================================================

_orders_cache = {}
_last_cron_time = 0


def get_orders_file():
    if os.environ.get("VERCEL") == "1":
        return "/tmp/orders.json"
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "orders.json")


def load_orders():
    global _orders_cache
    fpath = get_orders_file()
    if os.path.exists(fpath):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    _orders_cache.update(loaded)
        except Exception:
            pass
    return _orders_cache.copy()


def save_orders(orders):
    global _orders_cache
    if isinstance(orders, dict):
        _orders_cache.update(orders)
    fpath = get_orders_file()
    try:
        # Keep maximum 200 newest orders to save storage
        if len(_orders_cache) > 200:
            sorted_keys = sorted(_orders_cache.keys(), key=lambda k: _orders_cache[k].get("created_at", 0), reverse=True)
            _orders_cache = {k: _orders_cache[k] for k in sorted_keys[:200]}
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(_orders_cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        safe_print(f"[save_orders] Error: {e}")


@app.route("/api/payment/create-order", methods=["POST"])
def create_payment_order():
    data = request.get_json(silent=True) or {}
    raw_username = (data.get("username") or "").strip().lstrip("@")
    uid = (data.get("uid") or "").strip()
    package_type = (data.get("package_type") or "with_dns").strip()

    if not raw_username:
        return jsonify({"success": False, "msg": "Vui lòng nhập username / ID Locket."}), 400

    cfg_payment = config_manager.get_payment_config()
    packages = cfg_payment.get("packages", {})
    if package_type not in packages:
        package_type = "with_dns"

    pkg = packages.get(package_type, {})
    amount = int(pkg.get("price", 10000))
    amount_formatted = pkg.get("price_formatted", f"{amount:,}đ")

    orders = load_orders()

    # Nội dung chuyển khoản là ID Locket của khách (in hoa, chỉ gồm chữ & số để tương thích 100% mọi app ngân hàng)
    clean_id = re.sub(r"[^A-Za-z0-9]", "", raw_username).upper()
    if not clean_id:
        clean_id = re.sub(r"[^A-Za-z0-9]", "", uid).upper() if uid else f"LK{random.randint(1000, 9999)}"

    order_id = clean_id
    transfer_content = clean_id

    # Nếu mã này đã từng hoàn thành trước đó, lưu đơn cũ vào lịch sử để không bị ghi đè
    if order_id in orders and orders[order_id].get("status") == "COMPLETED":
        old_created = int(orders[order_id].get("created_at", 0))
        orders[f"{order_id}_{old_created}"] = orders[order_id]

    bank_id = cfg_payment.get("bank_id", "970454")
    bank_name = cfg_payment.get("bank_name", "Ngân Hàng Bản Việt (BVBank - ZaloPay)")
    account_no = cfg_payment.get("account_number", "99ZP24261M43061759")
    account_name = cfg_payment.get("account_name", "ZALOPAY_DINH TUAN HUNG")

    # Default VietQR fallback with customer's Locket ID
    qr_url = f"https://img.vietqr.io/image/{bank_id}-{account_no}-compact2.png?amount={amount}&addInfo={quote(transfer_content)}&accountName={quote(account_name)}"

    # Try calling thueapibank ZaloPay QR API with official token
    zalo_token = cfg_payment.get("thueapibank", {}).get("token") or "498705aae1752f7c0658c6f622317daf"
    if zalo_token:
        try:
            z_res = requests.post(
                "https://thueapibank.vn/zalopay/qrcode",
                data={"token": zalo_token, "amount": amount, "message": transfer_content},
                timeout=5
            )
            if z_res.status_code == 200:
                z_data = z_res.json()
                b64 = z_data.get("qrcode")
                if b64:
                    qr_url = f"data:image/png;base64,{b64}"
                if z_data.get("bank_number"):
                    account_no = z_data.get("bank_number")
                if z_data.get("bank_holder_name"):
                    account_name = z_data.get("bank_holder_name")
        except Exception as e:
            safe_print(f"[create_payment_order] thueapibank API error: {e}")

    orders[order_id] = {
        "order_id": order_id,
        "username": raw_username,
        "uid": uid,
        "package_type": package_type,
        "package_name": pkg.get("name", "Gói Locket Gold"),
        "amount": amount,
        "amount_formatted": amount_formatted,
        "status": "PENDING",  # PENDING -> PAID -> COMPLETED -> EXPIRED
        "created_at": time.time(),
        "created_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "qr_url": qr_url,
        "client_id": None,
        "transaction_id": None,
        "bank_name": bank_name,
        "account_no": account_no,
        "account_name": account_name,
        "content": transfer_content
    }
    save_orders(orders)

    return jsonify({
        "success": True,
        "order_id": order_id,
        "amount": amount,
        "amount_formatted": amount_formatted,
        "package_name": pkg.get("name", "Gói Locket Gold"),
        "qr_url": qr_url,
        "bank_name": bank_name,
        "account_no": account_no,
        "account_name": account_name,
        "content": transfer_content
    })


def check_and_process_zalopay_history():
    """Fetches latest transactions from thueapibank.vn for ZaloPay and matches with pending orders."""
    global _last_cron_time
    _last_cron_time = time.time()

    cfg_payment = config_manager.get_payment_config()
    zalo_token = cfg_payment.get("thueapibank", {}).get("token") or "498705aae1752f7c0658c6f622317daf"
    if not zalo_token:
        return {"status": "error", "success": False, "msg": "Chưa cấu hình token ZaloPay trong hệ thống."}

    orders = load_orders()
    changed = False

    # 1. Retry any pending activations that previously failed due to network/Locket API blips
    for oid, o in list(orders.items()):
        if o.get("status") == "PAID_PENDING_ACTIVATION":
            try:
                cid = queue_manager.add_to_queue(o["username"], o["package_type"])
                o["client_id"] = cid
                o["status"] = "COMPLETED"
                o["activation_error"] = None
                changed = True
                safe_print(f"[Cron Bank] Tự động kích hoạt bù Gold thành công cho @{o['username']}, cid={cid}")
            except Exception as ex:
                o["activation_error"] = str(ex)

    # 2. Fetch latest transactions from thueapibank.vn with retry and browser User-Agent
    url = f"https://thueapibank.vn/historyapizalopay/{zalo_token}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    res_data = None
    last_err = None
    for attempt in range(2):
        try:
            res = requests.get(url, headers=headers, timeout=(6, 15))
            if res.status_code == 200:
                res_data = res.json()
                break
            else:
                last_err = f"HTTP {res.status_code}"
        except Exception as e:
            last_err = str(e)
            time.sleep(1)

    if res_data is None:
        safe_print(f"[Cron Bank] Lỗi kết nối thueapibank: {last_err}")
        if changed:
            save_orders(orders)
        return {
            "status": "error",
            "success": False,
            "msg": f"Không thể kết nối đến thueapibank.vn: {last_err}",
            "pending_orders_count": len([o for o in orders.values() if o.get("status") == "PENDING"]),
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    raw_items = res_data.get("data", [])
    if not isinstance(raw_items, list):
        raw_items = []

    # 3. Collect already processed transaction IDs to prevent double activation
    used_tids = {
        str(o.get("transaction_id")).strip()
        for o in orders.values()
        if o.get("transaction_id") and o.get("status") in ("PAID", "COMPLETED")
    }

    matched_orders = []
    pending_orders = {oid: o for oid, o in orders.items() if o.get("status") == "PENDING"}

    # 4. Process each incoming transaction
    for item in raw_items:
        tx = item.get("data", {}).get("transaction") if (isinstance(item, dict) and isinstance(item.get("data"), dict) and "transaction" in item.get("data")) else (item if isinstance(item, dict) else {})

        # Check for incoming money (sign == 1 or trans_type == 11 or positive amount)
        is_incoming = (
            str(tx.get("sign")) == "1" or
            tx.get("trans_type") == 11 or
            str(item.get("sign")) == "1"
        )
        if not is_incoming:
            continue

        tid = str(tx.get("trans_id") or item.get("trans_id") or "").strip()
        if tid and tid in used_tids:
            continue

        # Extract amount
        raw_amt = tx.get("trans_amount") or tx.get("charge_amount") or tx.get("subtotal_amount") or item.get("trans_amount") or 0
        try:
            amt = int(float(str(raw_amt).replace(",", "").replace(".", "").strip()))
        except (ValueError, TypeError):
            amt = 0

        if amt <= 0:
            continue

        # Collect customer message from 'Lời nhắn' or 'trans_note'
        customer_msg_parts = []
        if tx.get("trans_note"):
            customer_msg_parts.append(str(tx.get("trans_note")))

        # Collect text notes from all possible places
        notes = [
            str(tx.get("description") or ""),
            str(tx.get("trans_note") or ""),
            str(tx.get("title") or ""),
            str(tx.get("app_trans_id") or ""),
            str(item.get("description") or ""),
            str(item.get("trans_note") or "")
        ]
        for cf in tx.get("template_info", {}).get("custom_fields", []) or []:
            if isinstance(cf, dict):
                cf_name = str(cf.get("name") or "").strip()
                cf_val = str(cf.get("value") or "").strip()
                notes.append(cf_val)
                # If this field is customer message (Lời nhắn / Nội dung / Ghi chú)
                if any(k in cf_name.lower() for k in ["lời nhắn", "loi nhan", "nội dung", "noi dung", "ghi chú", "ghi chu", "message", "note"]):
                    customer_msg_parts.append(cf_val)

        customer_msg = " ".join(customer_msg_parts).strip()
        full_text = " ".join(notes).upper()
        # Clean text: uppercase letters and digits only
        full_text_clean = re.sub(r"[^A-Z0-9]", "", full_text)
        # Normalize LOCKET -> LK
        full_text_normalized = re.sub(r"LOCKET", "LK", full_text_clean)

        matched_oid = None

        # Check against pending orders
        for oid, order in pending_orders.items():
            order_code = oid.upper()
            order_code_clean = re.sub(r"[^A-Z0-9]", "", order_code)
            order_code_normalized = re.sub(r"LOCKET", "LK", order_code_clean)
            username = str(order.get("username") or "").upper().lstrip("@")
            username_clean = re.sub(r"[^A-Z0-9]", "", username)
            uid_str = str(order.get("uid") or "").upper()
            uid_clean = re.sub(r"[^A-Z0-9]", "", uid_str)
            req_amount = int(order.get("amount", 0))

            is_match = False
            # Match 1: ID Locket (order_code) in transfer text
            if (order_code in full_text) or (order_code_clean and order_code_clean in full_text_clean) or (order_code_normalized in full_text_normalized):
                is_match = True
            # Match 2: username in transfer text (at least 3 characters)
            elif username_clean and len(username_clean) >= 3 and (username_clean in full_text_clean):
                is_match = True
            # Match 3: UID in transfer text (at least 10 characters)
            elif uid_clean and len(uid_clean) >= 10 and (uid_clean in full_text_clean):
                is_match = True

            if is_match and amt >= req_amount:
                matched_oid = oid
                break

        if matched_oid:
            order = pending_orders.pop(matched_oid)
            order["status"] = "PAID"
            order["transaction_id"] = tid
            order["paid_amount"] = amt
            order["paid_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if tid:
                used_tids.add(tid)

            # Activate Gold immediately
            try:
                cid = queue_manager.add_to_queue(order["username"], order["package_type"])
                order["client_id"] = cid
                order["status"] = "COMPLETED"
                order["activation_error"] = None
                safe_print(f"[Cron Bank] Khớp đơn {matched_oid} và kích hoạt Gold cho @{order['username']}, cid={cid}, TX: {tid}")
            except Exception as e:
                order["status"] = "PAID_PENDING_ACTIVATION"
                order["activation_error"] = str(e)
                safe_print(f"[Cron Bank] Đã nhận tiền đơn {matched_oid} nhưng lỗi kích hoạt: {e}")

            matched_orders.append({
                "order_id": matched_oid,
                "username": order["username"],
                "package_type": order["package_type"],
                "amount": amt,
                "trans_id": tid,
                "status": order["status"]
            })
            changed = True
        else:
            # Direct transfer without existing pending order (only from customer message)
            if amt >= 10000 and customer_msg:
                direct_candidates = []
                # Match @username
                at_matches = re.findall(r"@([A-Za-z0-9._]{3,30})", customer_msg)
                direct_candidates.extend(at_matches)

                # Match keyword patterns: LOCKET/GOLD/UP/ACC/TK username
                kw_matches = re.findall(r"(?:LOCKET|GOLD|UP|ACC|TK|USER)\s*[:=\s]+([A-Za-z0-9._]{3,30})", customer_msg, re.IGNORECASE)
                direct_candidates.extend(kw_matches)

                # Match if customer_msg is a single word token like "hungdinh206"
                words = customer_msg.strip().split()
                if len(words) == 1 and re.match(r"^[A-Za-z0-9._]{4,30}$", words[0]):
                    direct_candidates.append(words[0])

                ignore_words = {
                    "BANK", "MBBANK", "ZALOPAY", "VIETQR", "NAP", "TIEN", "CHUYEN",
                    "KHOAN", "NHAN", "QUA", "ZALO", "MA", "DON", "HANG", "NGUOI",
                    "GUI", "THE", "QUAN", "DOI", "THANH", "CONG", "LOCKET", "GOLD",
                    "TRIEU", "ANH", "MAI", "LUONG", "HOANG", "HUONG", "MINH", "DUY"
                }

                for candidate in direct_candidates:
                    cand_clean = candidate.lstrip("@").strip()
                    if len(cand_clean) >= 3 and cand_clean.upper() not in ignore_words and not cand_clean.isdigit():
                        try:
                            uid = api.resolve_uid(cand_clean)
                            if uid:
                                pkg_type = "with_dns" if amt >= 30000 else "no_dns"
                                new_oid = f"DIRECT{random.randint(1000, 9999)}"
                                safe_print(f"[Cron Bank] Tự động nhận diện CK trực tiếp cho @{cand_clean} ({uid}), gói {pkg_type}, {amt}đ, TX: {tid}")
                                cid = queue_manager.add_to_queue(cand_clean, pkg_type)
                                orders[new_oid] = {
                                    "order_id": new_oid,
                                    "username": cand_clean,
                                    "package_type": pkg_type,
                                    "package_name": "Giữ Gold" if pkg_type == "with_dns" else "Không Giữ Gold",
                                    "amount": amt,
                                    "amount_formatted": f"{amt:,}đ",
                                    "status": "COMPLETED",
                                    "client_id": cid,
                                    "transaction_id": tid,
                                    "paid_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "created_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "note": f"Tự động nhận diện từ CK ZaloPay ({tid})"
                                }
                                if tid:
                                    used_tids.add(tid)
                                matched_orders.append({
                                    "order_id": new_oid,
                                    "username": cand_clean,
                                    "package_type": pkg_type,
                                    "amount": amt,
                                    "trans_id": tid,
                                    "status": "COMPLETED"
                                })
                                changed = True
                                break
                        except Exception as ex:
                            safe_print(f"[Cron Bank] Thử nhận diện @{cand_clean} không thành công: {ex}")

    if changed:
        save_orders(orders)

    return {
        "status": "success",
        "success": True,
        "message": f"Quét ZaloPay thành công! Khớp {len(matched_orders)} đơn hàng.",
        "msg": f"Quét ZaloPay thành công! Khớp {len(matched_orders)} đơn hàng mới.",
        "matched": matched_orders,
        "matched_orders": matched_orders,
        "total_txs": len(raw_items),
        "total_txs_fetched": len(raw_items),
        "pending_orders_count": len([o for o in orders.values() if o.get("status") == "PENDING"]),
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


@app.route("/api/cron/bank", methods=["GET", "POST"], strict_slashes=False)
@app.route("/cron/bank", methods=["GET", "POST"], strict_slashes=False)
@app.route("/cron.php", methods=["GET", "POST"], strict_slashes=False)
@app.route("/api/cron.php", methods=["GET", "POST"], strict_slashes=False)
def cron_bank():
    res = check_and_process_zalopay_history()
    return jsonify(res), 200


@app.route("/api/payment/check", methods=["GET"])
def check_payment_status():
    order_id = (request.args.get("order_id") or "").strip().upper()
    if not order_id:
        return jsonify({"success": False, "msg": "Thiếu mã đơn hàng order_id."}), 400

    orders = load_orders()
    order = orders.get(order_id)

    # Self-healing on Vercel cold-starts / ephemeral containers:
    # If order is missing, reconstruct from query parameters passed by client browser!
    if not order:
        username = (request.args.get("username") or "").strip().lstrip("@")
        pkg = (request.args.get("package_type") or "with_dns").strip()
        try:
            amt = int(request.args.get("amount") or 30000)
        except Exception:
            amt = 30000
        if username:
            order = {
                "order_id": order_id,
                "username": username,
                "package_type": pkg,
                "package_name": "Giữ Gold" if pkg == "with_dns" else "Không Giữ Gold",
                "amount": amt,
                "amount_formatted": f"{amt:,}đ",
                "status": "PENDING",
                "created_at": time.time(),
                "created_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            orders[order_id] = order
            save_orders(orders)
        else:
            return jsonify({"success": False, "msg": "Không tìm thấy đơn hàng."}), 404

    # If pending and >3s since last cron check, automatically trigger cron scan!
    global _last_cron_time
    if order.get("status") == "PENDING" and (time.time() - _last_cron_time) > 3:
        try:
            check_and_process_zalopay_history()
            orders = load_orders()
            order = orders.get(order_id, order)
        except Exception as e:
            safe_print(f"[check_payment_status] Auto cron check error: {e}")

    is_paid = order.get("status") in ("PAID", "COMPLETED")
    return jsonify({
        "success": True,
        "order_id": order_id,
        "status": order.get("status"),
        "is_paid": is_paid,
        "client_id": order.get("client_id"),
        "msg": "Đã thanh toán thành công!" if is_paid else "Đang chờ thanh toán..."
    })


@app.route("/api/webhook/thueapibank", methods=["POST"])
def webhook_thueapibank():
    sig = request.headers.get("signature") or request.headers.get("Signature") or request.headers.get("X-Signature")

    cfg_payment = config_manager.get_payment_config()
    expected_sig = cfg_payment.get("thueapibank", {}).get("signature") or "b143315fbdacb0548e4141f4d9743157"

    if not sig or sig.strip().lower() != expected_sig.strip().lower():
        safe_print(f"[Webhook thueapibank] Chữ ký không hợp lệ: nhận={sig}, mong đợi={expected_sig}")
        return jsonify({"status": False, "msg": "Chữ ký không hợp lệ."}), 401

    payload = request.get_json(silent=True) or {}
    safe_print(f"[Webhook thueapibank] Nhận dữ liệu webhook: {json.dumps(payload)}")

    transactions = payload.get("transactions", [])
    if not isinstance(transactions, list):
        return jsonify({"status": True, "msg": "OK"}), 200

    orders = load_orders()
    changed = False

    for tx in transactions:
        tx_type = str(tx.get("type") or "").upper()
        if tx_type != "IN":
            continue

        tx_id = str(tx.get("transactionID") or "")
        desc = str(tx.get("description") or "").upper()
        try:
            amount = int(float(tx.get("amount") or 0))
        except Exception:
            amount = 0

        safe_print(f"[Webhook thueapibank] Giao dịch vào: ID={tx_id}, Số tiền={amount}, Nội dung={desc}")

        # Match against all pending orders
        for oid, order in orders.items():
            if order.get("status") not in ("PENDING",):
                continue

            order_code = oid.upper()
            username = str(order.get("username") or "").upper().lstrip("@")
            req_amount = int(order.get("amount") or 0)

            # Match criteria: description contains order code (e.g. LK1234) or username
            is_matched = (order_code in desc) or (username and len(username) >= 3 and username in desc)
            if is_matched and amount >= req_amount:
                safe_print(f"[Webhook thueapibank] Khớp đơn {oid} cho @{order.get('username')}, tiền={amount}đ")
                order["status"] = "PAID"
                order["transaction_id"] = tx_id
                order["paid_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Auto activate Gold immediately
                try:
                    cid = queue_manager.add_to_queue(order["username"], order["package_type"])
                    order["client_id"] = cid
                    order["status"] = "COMPLETED"
                    safe_print(f"[Webhook thueapibank] Kích hoạt Gold xong cho @{order['username']}, cid={cid}")
                except Exception as e:
                    safe_print(f"[Webhook thueapibank] Lỗi kích hoạt Gold: {e}")

                changed = True
                break

    if changed:
        save_orders(orders)

    return jsonify({"status": True, "msg": "OK"}), 200


@app.route("/api/restore", methods=["POST"])
def restore_purchase():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"success": False, "msg": "Dữ liệu yêu cầu không hợp lệ."}), 400

    username = (data.get("username") or "").strip().lstrip("@")
    package_type = data.get("package_type", "with_dns")
    order_id = (data.get("order_id") or "").strip().upper()

    current_payment = config_manager.get_payment_config()
    if package_type not in current_payment.get("packages", {}):
        package_type = "with_dns"

    if not username:
        return jsonify({"success": False, "msg": "Vui lòng nhập username Locket."}), 400

    orders = load_orders()

    # If order_id is provided, verify it has been paid!
    if order_id:
        order = orders.get(order_id)
        if not order:
            return jsonify({"success": False, "msg": f"Mã đơn hàng {order_id} không tồn tại."}), 404
        if order.get("status") not in ("PAID", "COMPLETED"):
            return jsonify({"success": False, "msg": "Đơn hàng chưa được hệ thống ghi nhận thanh toán."}), 400
        if order.get("client_id"):
            status = queue_manager.get_status(order["client_id"])
            if status:
                return jsonify({
                    "success": True,
                    "client_id": order["client_id"],
                    "package_type": package_type,
                    "position": status["position"],
                    "total_queue": status["total_queue"],
                    "estimated_time": status["estimated_time"],
                })

    try:
        client_id = queue_manager.add_to_queue(username, package_type)
        if order_id and order_id in orders:
            orders[order_id]["client_id"] = client_id
            orders[order_id]["status"] = "COMPLETED"
            save_orders(orders)

        status = queue_manager.get_status(client_id)

        return jsonify({
            "success": True,
            "client_id": client_id,
            "package_type": package_type,
            "position": status["position"],
            "total_queue": status["total_queue"],
            "estimated_time": status["estimated_time"],
        })
    except Exception as e:
        safe_print(f"[restore_purchase] Error: {e}")
        return jsonify({"success": False, "msg": f"Lỗi hệ thống: {str(e)}"}), 500


@app.route("/api/queue/status", methods=["POST"])
def queue_status():
    data = request.get_json(silent=True) or {}
    client_id = (data.get("client_id") or "").strip()
    if not client_id:
        return jsonify({"success": False, "msg": "client_id is required."}), 400

    status = queue_manager.get_status(client_id)
    if status is None:
        return jsonify({"success": False, "msg": "Không tìm thấy phiên xử lý."}), 404

    return jsonify({"success": True, **status})


# ==============================================================================
# --- Admin API Endpoints ---
# ==============================================================================

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}
    pwd = data.get("password", "")
    if config_manager.verify_password(pwd):
        return jsonify({"success": True, "token": pwd, "msg": "Đăng nhập thành công!"})
    return jsonify({"success": False, "msg": "Mật khẩu Admin không chính xác!"}), 401


@app.route("/api/admin/config", methods=["GET"])
@admin_required
def get_admin_config():
    return jsonify({
        "success": True,
        "data": {
            "payment": config_manager.get_payment_config(),
            "telegram": config_manager.get_telegram_config(),
            "tokens_summary": config_manager.get_token_sets_summaries(),
            "revenuecat_bearer": config_manager.get_api_tokens().get("revenuecat_bearer", ""),
            "firebase_appcheck": config_manager.get_api_tokens().get("firebase_appcheck", ""),
            "locket_bearer": config_manager.get_api_tokens().get("locket_bearer", ""),
        }
    })


@app.route("/api/admin/price", methods=["POST"])
@admin_required
def update_admin_price():
    data = request.get_json(silent=True) or {}
    success, msg = config_manager.update_package_price(
        data.get("package_id"),
        data.get("price"),
        data.get("name"),
        data.get("badge"),
        data.get("desc"),
        data.get("warning")
    )
    return jsonify({"success": success, "msg": msg}), (200 if success else 400)


@app.route("/api/admin/bank", methods=["POST"])
@admin_required
def update_admin_bank():
    data = request.get_json(silent=True) or {}
    success, msg = config_manager.update_bank_info(
        data.get("bank_id", ""),
        data.get("bank_name", ""),
        data.get("account_number", ""),
        data.get("account_name", "")
    )
    return jsonify({"success": success, "msg": msg}), (200 if success else 400)


@app.route("/api/admin/tokens", methods=["GET"])
@admin_required
def get_admin_tokens():
    tokens = config_manager.get_api_tokens()
    return jsonify({
        "success": True,
        "token_sets": config_manager.get_token_sets_summaries(),
        "revenuecat_bearer": tokens.get("revenuecat_bearer", ""),
        "firebase_appcheck": tokens.get("firebase_appcheck", ""),
        "locket_bearer": tokens.get("locket_bearer", ""),
    })


@app.route("/api/admin/tokens/add", methods=["POST"])
@admin_required
def add_admin_token():
    data = request.get_json(silent=True) or {}
    token_data = {
        "name": data.get("name") or f"Token {time.strftime('%d/%m %H:%M')}",
        "fetch_token": data.get("fetch_token", "").strip(),
        "app_transaction": data.get("app_transaction", "").strip(),
        "transaction_id": str(data.get("transaction_id", "570002518164026")).strip(),
        "product_id": data.get("product_id", "locket_199_1m").strip(),
        "hash_params": data.get("hash_params", "").strip(),
        "hash_headers": data.get("hash_headers", "").strip(),
        "is_sandbox": bool(data.get("is_sandbox", False)),
        "active": True
    }
    success, msg = config_manager.add_token_set(token_data)
    return jsonify({"success": success, "msg": msg}), (200 if success else 400)


@app.route("/api/admin/tokens/import-raw", methods=["POST"])
@admin_required
def import_raw_token():
    data = request.get_json(silent=True) or {}
    raw_text = data.get("text", "")
    extracted, err = parse_raw_token_request(raw_text)
    if err:
        return jsonify({"success": False, "msg": err}), 400

    custom_name = data.get("name")
    if custom_name and custom_name.strip():
        extracted["name"] = custom_name.strip()

    test_result = test_restore_token(extracted)
    if test_result.get("success"):
        extracted["last_tested"] = datetime.now().strftime("%d/%m %H:%M")
        extracted["test_status"] = "200_OK"
    else:
        extracted["last_tested"] = datetime.now().strftime("%d/%m %H:%M")
        extracted["test_status"] = f"HTTP_{test_result.get('status_code', 0)}"

    success, msg = config_manager.add_token_set(extracted)
    return jsonify({
        "success": success,
        "msg": msg,
        "token": get_token_summary(extracted),
        "live_test": test_result
    }), (200 if success else 400)


@app.route("/api/admin/tokens/toggle", methods=["POST"])
@admin_required
def toggle_admin_token():
    data = request.get_json(silent=True) or {}
    token_id = data.get("token_id")
    success, res = config_manager.toggle_token_set(token_id)
    return jsonify({
        "success": success,
        "active": res if success else False,
        "msg": "Đã đổi trạng thái token." if success else str(res)
    }), (200 if success else 400)


@app.route("/api/admin/tokens/delete", methods=["POST"])
@admin_required
def delete_admin_token():
    data = request.get_json(silent=True) or {}
    token_id = data.get("token_id")
    success, msg = config_manager.delete_token_set(token_id)
    return jsonify({"success": success, "msg": msg}), (200 if success else 400)


@app.route("/api/admin/tokens/test", methods=["POST"])
@admin_required
def test_admin_token():
    data = request.get_json(silent=True) or {}
    token_id = data.get("token_id")
    token_config = None
    for t in config_manager.get_token_sets():
        if t.get("id") == token_id:
            token_config = t
            break
    if not token_config:
        return jsonify({"success": False, "msg": "Không tìm thấy token."}), 404

    test_result = test_restore_token(token_config)
    status_label = "200_OK" if test_result.get("success") else f"HTTP_{test_result.get('status_code', 0)}"
    config_manager.update_token_set(token_id, {
        "last_tested": datetime.now().strftime("%d/%m %H:%M"),
        "test_status": status_label
    })
    return jsonify(test_result)


@app.route("/api/admin/tokens/advanced", methods=["POST"])
@admin_required
def update_admin_advanced_tokens():
    data = request.get_json(silent=True) or {}
    if "revenuecat_bearer" in data:
        config_manager.set_revenuecat_bearer(data["revenuecat_bearer"])
    if "firebase_appcheck" in data:
        config_manager.set_firebase_appcheck(data["firebase_appcheck"])
    if "locket_bearer" in data:
        config_manager.set_locket_bearer(data["locket_bearer"])
    return jsonify({"success": True, "msg": "Cập nhật cấu hình API nâng cao thành công."})


@app.route("/api/admin/locket/login", methods=["POST"])
@admin_required
def admin_locket_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    pwd = (data.get("password") or "").strip()
    if not email or not pwd:
        return jsonify({"success": False, "msg": "Vui lòng nhập Email và Mật khẩu Locket."}), 400

    try:
        url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=AIzaSyCQngaaXQIfJaH0aS2l7REgIjD7nL431So"
        headers = {
            "X-Ios-Bundle-Identifier": "com.locket.Locket",
            "User-Agent": "Locket/2283 CFNetwork/3896.100.1.2.1 Darwin/27.0.0",
        }
        res = requests.post(
            url,
            headers=headers,
            json={"email": email, "password": pwd, "returnSecureToken": True},
            timeout=10,
        )
        res_data = res.json()
        if not res.ok:
            err_code = res_data.get("error", {}).get("message", "Đăng nhập thất bại")
            trans = {
                "EMAIL_NOT_FOUND": "Email này chưa được đăng ký tài khoản Locket.",
                "INVALID_PASSWORD": "Mật khẩu không chính xác.",
                "USER_DISABLED": "Tài khoản Locket đã bị vô hiệu hóa.",
            }
            msg = trans.get(err_code, f"Lỗi từ Locket: {err_code}")
            return jsonify({"success": False, "msg": msg}), 400

        id_token = res_data.get("idToken")
        refresh_token = res_data.get("refreshToken")
        config_manager.set_locket_bearer(id_token)
        if refresh_token:
            config_manager.set_locket_refresh_token(refresh_token)
        return jsonify({
            "success": True,
            "msg": "Đăng nhập thành công! Đã tự động cập nhật Locket Bearer Token.",
            "token": id_token,
        })
    except Exception as e:
        return jsonify({"success": False, "msg": f"Lỗi kết nối: {str(e)}"}), 500


@app.route("/api/admin/tokens/import-locket-raw", methods=["POST"])
@admin_required
def import_locket_raw_token():
    import re
    data = request.get_json(silent=True) or {}
    raw_text = data.get("text", "")
    if not raw_text:
        return jsonify({"success": False, "msg": "Vui lòng dán nội dung gói tin HTTP Catcher."}), 400

    auth_match = re.search(r"authorization:\s*(Bearer\s+[A-Za-z0-9_\-\.]+)", raw_text, re.IGNORECASE)
    appcheck_match = re.search(r"x-firebase-appcheck:\s*([A-Za-z0-9_\-\.]+)", raw_text, re.IGNORECASE)
    iid_match = re.search(r"firebase-instance-id-token:\s*([^\s\r\n]+)", raw_text, re.IGNORECASE)

    extracted_bearer = auth_match.group(1).strip() if auth_match else ""
    if not extracted_bearer:
        jwt_match = re.search(r"(Bearer\s+eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", raw_text)
        if jwt_match:
            extracted_bearer = jwt_match.group(1).strip()

    extracted_appcheck = appcheck_match.group(1).strip() if appcheck_match else ""
    extracted_iid = iid_match.group(1).strip() if iid_match else ""

    if not extracted_bearer and not extracted_appcheck:
        return jsonify({"success": False, "msg": "Không tìm thấy header Authorization hoặc X-Firebase-AppCheck trong gói tin."}), 400

    tokens = config_manager.get_data().setdefault("api_tokens", {})
    if extracted_bearer:
        config_manager.set_locket_bearer(extracted_bearer)
        try:
            raw_jwt = extracted_bearer.replace("Bearer ", "").strip()
            decoded = decode_jwt_payload(raw_jwt) or {}
            tokens["locket_account_email"] = decoded.get("email") or tokens.get("locket_account_email", "")
            tokens["locket_account_name"] = decoded.get("name") or tokens.get("locket_account_name", "")
            tokens["locket_account_uid"] = decoded.get("user_id") or decoded.get("sub") or tokens.get("locket_account_uid", "")
        except Exception:
            pass

    if extracted_appcheck:
        config_manager.set_firebase_appcheck(extracted_appcheck)
    if extracted_iid:
        tokens["firebase_instance_id_token"] = extracted_iid

    config_manager.save()

    return jsonify({
        "success": True,
        "msg": "Đã bóc tách và lưu Authorization & AppCheck từ gói tin thành công!",
        "locket_bearer": extracted_bearer,
        "firebase_appcheck": extracted_appcheck,
    })


@app.route("/api/admin/password", methods=["POST"])
@admin_required
def update_admin_password():
    data = request.get_json(silent=True) or {}
    new_pwd = (data.get("new_password") or "").strip()
    success, msg = config_manager.set_admin_password(new_pwd)
    return jsonify({"success": success, "msg": msg}), (200 if success else 400)


@app.route("/api/admin/telegram", methods=["POST"])
@admin_required
def update_admin_telegram():
    data = request.get_json(silent=True) or {}
    success, msg = config_manager.update_telegram(data.get("bot_token", ""), data.get("chat_id", ""))
    return jsonify({"success": success, "msg": msg})


@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def get_admin_stats():
    stats = queue_manager.get_stats()
    stats["active_tokens_count"] = len(config_manager.get_active_token_sets())
    stats["total_tokens_count"] = len(config_manager.get_token_sets())
    return jsonify({"success": True, "data": stats})


@app.route("/api/admin/orders", methods=["GET"])
@admin_required
def get_admin_orders():
    orders = load_orders()
    sorted_orders = sorted(orders.values(), key=lambda o: o.get("created_at", 0), reverse=True)
    return jsonify({"success": True, "orders": sorted_orders})


@app.route("/api/admin/orders/approve", methods=["POST"])
@admin_required
def approve_admin_order():
    data = request.get_json(silent=True) or {}
    order_id = (data.get("order_id") or "").strip().upper()
    orders = load_orders()
    order = orders.get(order_id)
    if not order:
        return jsonify({"success": False, "msg": "Không tìm thấy đơn hàng."}), 404

    order["status"] = "PAID"
    order["paid_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " (Admin duyệt)"

    try:
        cid = queue_manager.add_to_queue(order["username"], order["package_type"])
        order["client_id"] = cid
        order["status"] = "COMPLETED"
        save_orders(orders)
        return jsonify({"success": True, "msg": f"Đã duyệt và kích hoạt Gold cho @{order['username']}!", "client_id": cid})
    except Exception as e:
        save_orders(orders)
        return jsonify({"success": False, "msg": f"Lỗi kích hoạt: {e}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
