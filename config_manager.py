import os
import json
import base64
import time
import re
from datetime import datetime

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
if os.environ.get("VERCEL") == "1":
    TMP_CONFIG = "/tmp/config.json"
    if not os.path.exists(TMP_CONFIG) and os.path.exists(CONFIG_FILE):
        try:
            import shutil
            shutil.copyfile(CONFIG_FILE, TMP_CONFIG)
        except Exception:
            pass
    if os.path.exists(TMP_CONFIG):
        CONFIG_FILE = TMP_CONFIG

DEFAULT_TOKEN_SET = {
    "id": "token_default",
    "name": "Token mặc định (iOS StoreKit 2)",
    "fetch_token": "",
    "app_transaction": ""
}
DEFAULT_CONFIG = {
    "admin_password": "admin",
    "payment": {
        "bank_id": "MB",
        "bank_name": "MB Bank (Ngân Hàng Quân Đội)",
        "account_number": "",
        "account_name": "",
        "packages": {
            "no_dns": {
                "id": "no_dns",
                "name": "Không Giữ Gold",
                "price": 10000,
                "price_formatted": "10.000đ",
                "badge": "Tiết Kiệm",
                "desc": "Kích hoạt Locket Gold nhanh gọn",
                "warning": "Có thể mất bất kì lúc nào khi Locket quét",
                "has_dns": False
            },
            "with_dns": {
                "id": "with_dns",
                "name": "Giữ Gold (Vĩnh Viễn)",
                "price": 30000,
                "price_formatted": "30.000đ",
                "badge": "Khuyên Dùng ⭐",
                "desc": "Kích hoạt Locket Gold + Chống thu hồi",
                "warning": "Mở tải DNS để giữ Gold vĩnh viễn trên iOS",
                "has_dns": True
            }
        }
    },
    "api_tokens": {
        "revenuecat_bearer": "",
        "firebase_appcheck": "",
        "token_sets": [DEFAULT_TOKEN_SET]
    },
    "telegram": {
        "bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
        "chat_id": os.getenv("TELEGRAM_CHAT_ID", "")
    }
}


def format_currency_vnd(amount):
    """Format integer/float amount to VND display string (e.g. 10000 -> 10.000đ)."""
    try:
        val = int(amount)
        return f"{val:,}".replace(",", ".") + "đ"
    except Exception:
        return f"{amount}đ"


def decode_jwt_payload(token_str):
    """Decode JWT payload (part 2) without verifying signature to inspect expiration and details."""
    if not token_str or not isinstance(token_str, str):
        return None
    parts = token_str.strip().split(".")
    if len(parts) < 2:
        return None
    try:
        # Base64url decode payload
        payload_b64 = parts[1]
        # Pad payload to multiple of 4
        remainder = len(payload_b64) % 4
        if remainder > 0:
            payload_b64 += "=" * (4 - remainder)
        decoded_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded_bytes.decode("utf-8", errors="replace"))
    except Exception:
        return None


def get_token_summary(token_set):
    """Analyze token_set and extract expiration, product_id, validity status."""
    info = {
        "id": token_set.get("id"),
        "name": token_set.get("name", "Unnamed Token"),
        "active": token_set.get("active", True),
        "is_sandbox": token_set.get("is_sandbox", False),
        "product_id": token_set.get("product_id", "locket_199_1m"),
        "subscription_period": "Gói 1 Tháng",
        "transaction_id": token_set.get("transaction_id", ""),
        "created_at": token_set.get("created_at", ""),
        "purchase_date": None,
        "original_purchase_date": None,
        "signed_date": None,
        "expires_at": None,
        "is_expired": False,
        "days_diff": 0,
        "days_text": "",
        "status_text": "Hoạt động",
        "compatibility": "Dùng vĩnh viễn với gói Giữ Gold (DNS)",
        "expiry_note": "",
        "environment": "Production",
        "has_fetch_token": bool(token_set.get("fetch_token")),
        "has_app_transaction": bool(token_set.get("app_transaction")),
        "has_hashes": bool(token_set.get("hash_params") and token_set.get("hash_headers")),
        "last_tested": token_set.get("last_tested", None),
        "test_status": token_set.get("test_status", None),
    }

    # Inspect both tokens (fetch_token and app_transaction) to find StoreKit 2 transaction info
    candidates = [
        decode_jwt_payload(token_set.get("fetch_token", "")),
        decode_jwt_payload(token_set.get("app_transaction", ""))
    ]

    for data in candidates:
        if not data or not isinstance(data, dict):
            continue
        if "productId" in data and not info.get("product_id"):
            info["product_id"] = data["productId"]
        if "environment" in data and not info.get("environment"):
            info["environment"] = data["environment"]
        if "transactionId" in data and not info.get("transaction_id"):
            info["transaction_id"] = str(data["transactionId"])
        if "originalPurchaseDate" in data and not info.get("original_purchase_date"):
            try:
                opts = int(data["originalPurchaseDate"]) / 1000
                info["original_purchase_date"] = datetime.fromtimestamp(opts).strftime("%d/%m/%Y %H:%M:%S")
            except Exception:
                pass
        if "purchaseDate" in data and not info.get("purchase_date"):
            try:
                pts = int(data["purchaseDate"]) / 1000
                info["purchase_date"] = datetime.fromtimestamp(pts).strftime("%d/%m/%Y %H:%M:%S")
            except Exception:
                pass
        if "signedDate" in data and not info.get("signed_date"):
            try:
                sts = int(data["signedDate"]) / 1000
                info["signed_date"] = datetime.fromtimestamp(sts).strftime("%d/%m/%Y %H:%M:%S")
            except Exception:
                pass
        if "expiresDate" in data and not info.get("expires_at"):
            try:
                exp_ts = int(data["expiresDate"]) / 1000
                exp_dt = datetime.fromtimestamp(exp_ts)
                now_ts = datetime.now().timestamp()
                info["expires_at"] = exp_dt.strftime("%d/%m/%Y %H:%M:%S")
                diff = int((exp_ts - now_ts) / 86400)
                info["days_diff"] = diff
                if diff >= 0:
                    info["is_expired"] = False
                    info["days_text"] = f"Còn {diff} ngày"
                    info["status_text"] = f"Còn hạn ({diff} ngày)"
                    info["compatibility"] = "Dùng tốt cho tất cả các gói"
                    info["expiry_note"] = f"Còn {diff} ngày chu kỳ thanh toán Apple. Hoạt động hoàn hảo cho mọi gói bán."
                else:
                    info["is_expired"] = True
                    abs_days = abs(diff)
                    info["days_text"] = f"Quá hạn {abs_days} ngày"
                    info["status_text"] = f"Hết hạn chu kỳ ({abs_days} ngày trước)"
                    info["compatibility"] = "Dùng vĩnh viễn với gói Giữ Gold (DNS)"
                    info["expiry_note"] = f"Chu kỳ Apple gốc kết thúc vào {info['expires_at']} ({abs_days} ngày trước). RevenueCat vẫn kích hoạt thành công (Live 200 OK) và tài khoản cài cấu hình DNS (gói 30k) sẽ được GIỮ GOLD VĨNH VIỄN."
            except Exception:
                pass
        elif "exp" in data and not info.get("expires_at"):
            try:
                exp_ts = int(data["exp"])
                exp_dt = datetime.fromtimestamp(exp_ts)
                now_ts = datetime.now().timestamp()
                info["expires_at"] = exp_dt.strftime("%d/%m/%Y %H:%M:%S")
                diff = int((exp_ts - now_ts) / 86400)
                info["days_diff"] = diff
                if diff >= 0:
                    info["is_expired"] = False
                    info["days_text"] = f"Còn {diff} ngày"
                    info["status_text"] = f"Còn hạn ({diff} ngày)"
                    info["compatibility"] = "Dùng tốt cho tất cả các gói"
                    info["expiry_note"] = f"Còn {diff} ngày chu kỳ thanh toán Apple."
                else:
                    info["is_expired"] = True
                    abs_days = abs(diff)
                    info["days_text"] = f"Quá hạn {abs_days} ngày"
                    info["status_text"] = f"Hết hạn chu kỳ ({abs_days} ngày trước)"
                    info["compatibility"] = "Dùng vĩnh viễn với gói Giữ Gold (DNS)"
                    info["expiry_note"] = f"Chu kỳ Apple gốc kết thúc vào {info['expires_at']} ({abs_days} ngày trước). Giữ Gold vĩnh viễn qua DNS."
            except Exception:
                pass

    pid = (info.get("product_id") or "").lower()
    if "1m" in pid or "month" in pid:
        info["subscription_period"] = "Gói 1 Tháng"
    elif "1y" in pid or "year" in pid:
        info["subscription_period"] = "Gói 1 Năm"
    elif "life" in pid:
        info["subscription_period"] = "Gói Vĩnh Viễn"
    else:
        info["subscription_period"] = "Gói Thuê Bao"

    return info


def parse_raw_token_request(raw_text):
    """
    Parse raw HTTP request, Proxyman, Charles, cURL, or JSON payload to extract:
    - fetch_token
    - app_transaction
    - transaction_id
    - product_id
    - hash_params (X-Post-Params-Hash)
    - hash_headers (X-Headers-Hash)
    - is_sandbox (X-Is-Sandbox)
    - revenuecat_bearer (Authorization: Bearer appl_...)
    """
    if not raw_text or not isinstance(raw_text, str):
        return None, "Nội dung đầu vào trống."

    text = raw_text.strip()
    extracted = {
        "name": f"Imported {datetime.now().strftime('%d/%m %H:%M:%S')}",
        "is_sandbox": False,
        "active": True,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # 1. Try JSON directly or search for embedded JSON object in text
    try:
        json_obj = None
        if text.startswith("{") and text.endswith("}"):
            json_obj = json.loads(text)
        else:
            json_match = re.search(r"(\{[\s\S]*\})", text)
            if json_match:
                try:
                    json_obj = json.loads(json_match.group(1))
                except Exception:
                    pass

        if isinstance(json_obj, dict):
            if "fetch_token" in json_obj:
                extracted["fetch_token"] = json_obj["fetch_token"]
            if "app_transaction" in json_obj:
                extracted["app_transaction"] = json_obj["app_transaction"]
            if "transaction_id" in json_obj:
                extracted["transaction_id"] = str(json_obj["transaction_id"])
            if "product_id" in json_obj:
                extracted["product_id"] = json_obj["product_id"]
            if "price" in json_obj:
                extracted["price"] = str(json_obj["price"])
            if "currency" in json_obj:
                extracted["currency"] = str(json_obj["currency"])
            if "store_country" in json_obj:
                extracted["store_country"] = str(json_obj["store_country"])
            if "subscription_group_id" in json_obj:
                extracted["subscription_group_id"] = str(json_obj["subscription_group_id"])
    except Exception:
        pass

    # 2. Regex extractors for headers and JSON fields inside raw text
    patterns = {
        "hash_params": [
            r"x-post-params-hash:\s*([a-zA-Z0-9_,:\-]+)",
            r'["\']x-post-params-hash["\']\s*:\s*["\']([^"\']+)["\']',
            r"-H\s+['\"]x-post-params-hash:\s*([^'\"]+)['\"]"
        ],
        "hash_headers": [
            r"x-headers-hash:\s*([a-zA-Z0-9_,:\-]+)",
            r'["\']x-headers-hash["\']\s*:\s*["\']([^"\']+)["\']',
            r"-H\s+['\"]x-headers-hash:\s*([^'\"]+)['\"]"
        ],
        "is_sandbox": [
            r"x-is-sandbox:\s*(true|false)",
            r'["\']x-is-sandbox["\']\s*:\s*["\']?(true|false)["\']?',
            r"-H\s+['\"]x-is-sandbox:\s*(true|false)['\"]"
        ],
        "fetch_token": [
            r'["\']fetch_token["\']\s*:\s*["\']([^"\']+)["\']',
            r"fetch_token=([A-Za-z0-9_\-\.\s]+)"
        ],
        "app_transaction": [
            r'["\']app_transaction["\']\s*:\s*["\']([^"\']+)["\']',
            r"app_transaction=([A-Za-z0-9_\-\.\s]+)"
        ],
        "transaction_id": [
            r'["\']transaction_id["\']\s*:\s*["\']?([0-9]+)["\']?',
            r"transaction_id=([0-9]+)"
        ],
        "product_id": [
            r'["\']product_id["\']\s*:\s*["\']([^"\']+)["\']',
            r"product_id=([A-Za-z0-9_\-\.]+)"
        ],
        "bearer_token": [
            r"[Aa]uthorization:\s*(Bearer\s+appl_[A-Za-z0-9_]+)",
            r"-H\s+['\"][Aa]uthorization:\s*(Bearer\s+appl_[A-Za-z0-9_]+)['\"]"
        ]
    }

    for key, regex_list in patterns.items():
        if key in extracted and extracted[key]:
            continue
        for p in regex_list:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if key == "is_sandbox":
                    extracted["is_sandbox"] = (val.lower() == "true")
                elif key == "bearer_token":
                    extracted["revenuecat_bearer"] = val
                else:
                    extracted[key] = val
                break

    # Clean any whitespace or newlines inside tokens
    if extracted.get("fetch_token"):
        extracted["fetch_token"] = re.sub(r"[\s\r\n]+", "", str(extracted["fetch_token"]))
    if extracted.get("app_transaction"):
        extracted["app_transaction"] = re.sub(r"[\s\r\n]+", "", str(extracted["app_transaction"]))

    # Check minimum required tokens or search whole text without linebreaks
    if not extracted.get("fetch_token") or not extracted.get("app_transaction"):
        clean_oneline_text = re.sub(r"[\s\r\n]+", "", text)
        jwt_matches = re.findall(r"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", clean_oneline_text)
        if len(jwt_matches) >= 2:
            if not extracted.get("fetch_token"):
                extracted["fetch_token"] = jwt_matches[0]
            if not extracted.get("app_transaction"):
                extracted["app_transaction"] = jwt_matches[1]

    if not extracted.get("fetch_token") or not extracted.get("app_transaction"):
        return None, "Không tìm thấy 'fetch_token' hoặc 'app_transaction' trong nội dung bạn dán."

    # Auto-detect if fetch_token and app_transaction were inverted (StoreKit 2 JWS format)
    ft_payload = decode_jwt_payload(extracted["fetch_token"]) or {}
    at_payload = decode_jwt_payload(extracted["app_transaction"]) or {}
    if "receiptType" in ft_payload and "transactionId" in at_payload:
        # Swap them back to correct fields
        extracted["fetch_token"], extracted["app_transaction"] = extracted["app_transaction"], extracted["fetch_token"]
        ft_payload, at_payload = at_payload, ft_payload

    # Default fallback values
    if not extracted.get("transaction_id"):
        extracted["transaction_id"] = str(ft_payload.get("transactionId") or "570002518164026")
    if not extracted.get("product_id"):
        extracted["product_id"] = str(ft_payload.get("productId") or "locket_199_1m")
    if "hash_params" not in extracted:
        extracted["hash_params"] = ""
    else:
        extracted["hash_params"] = extracted["hash_params"].strip()
    if "hash_headers" not in extracted:
        extracted["hash_headers"] = ""
    else:
        extracted["hash_headers"] = extracted["hash_headers"].strip()

    # Generate a readable name using the token info
    token_info = get_token_summary(extracted)
    exp_suffix = f" (Hạn: {token_info['expires_at'].split(' ')[0]})" if token_info.get("expires_at") else ""
    extracted["name"] = f"Token iOS {datetime.now().strftime('%d/%m %H:%M')}{exp_suffix}"
    extracted["id"] = f"token_{int(time.time())}"

    return extracted, None


class ConfigManager:
    def __init__(self, config_path=CONFIG_FILE):
        self.config_path = config_path
        self._data = None
        self.load()

    def load(self):
        """Load configuration from config.json or initialize with defaults."""
        if not os.path.exists(self.config_path):
            self._data = json.loads(json.dumps(DEFAULT_CONFIG))
            self.save()
            return self._data

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            # Ensure all keys from DEFAULT_CONFIG are present
            merged = json.loads(json.dumps(DEFAULT_CONFIG))
            self._deep_update(merged, loaded)
            self._data = merged
        except Exception as e:
            print(f"Warning: Failed to load {self.config_path}: {e}. Using defaults.")
            self._data = json.loads(json.dumps(DEFAULT_CONFIG))

        return self._data

    def _deep_update(self, base, update):
        for k, v in update.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                self._deep_update(base[k], v)
            else:
                base[k] = v

    def save(self):
        """Persist current configuration to config.json."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            if os.environ.get("VERCEL") == "1" and self.config_path != "/tmp/config.json":
                try:
                    self.config_path = "/tmp/config.json"
                    with open(self.config_path, "w", encoding="utf-8") as f:
                        json.dump(self._data, f, indent=2, ensure_ascii=False)
                    return True
                except Exception as inner_e:
                    print(f"Error saving to /tmp/config.json: {inner_e}")
            print(f"Error saving {self.config_path}: {e}")
            return False

    def get_data(self):
        if self._data is None:
            self.load()
        return self._data

    # Admin Password
    def verify_password(self, password):
        return str(password) == str(self.get_data().get("admin_password", "admin"))

    def set_admin_password(self, new_password):
        if not new_password or not str(new_password).strip():
            return False, "Mật khẩu không được để trống."
        self.get_data()["admin_password"] = str(new_password).strip()
        self.save()
        return True, "Cập nhật mật khẩu thành công."

    # Payment & Packages
    def get_payment_config(self):
        data = self.get_data().get("payment", {})
        # Ensure price_formatted are up to date
        for pkg_id, pkg in data.get("packages", {}).items():
            if "price" in pkg:
                pkg["price_formatted"] = format_currency_vnd(pkg["price"])
        return data

    def update_package_price(self, package_id, price, name=None, badge=None, desc=None, warning=None):
        payment = self.get_data().setdefault("payment", {})
        packages = payment.setdefault("packages", {})
        if package_id not in packages:
            return False, f"Gói '{package_id}' không tồn tại."

        pkg = packages[package_id]
        try:
            num_price = int(price)
            if num_price < 0:
                return False, "Giá tiền không được nhỏ hơn 0."
            pkg["price"] = num_price
            pkg["price_formatted"] = format_currency_vnd(num_price)
        except (ValueError, TypeError):
            return False, "Giá tiền phải là số hợp lệ."

        if name:
            pkg["name"] = str(name).strip()
        if badge:
            pkg["badge"] = str(badge).strip()
        if desc:
            pkg["desc"] = str(desc).strip()
        if warning is not None:
            pkg["warning"] = str(warning).strip()

        self.save()
        return True, "Cập nhật giá gói thành công."

    def update_bank_info(self, bank_id, bank_name, account_number, account_name):
        payment = self.get_data().setdefault("payment", {})
        payment["bank_id"] = str(bank_id).strip().upper()
        payment["bank_name"] = str(bank_name).strip()
        payment["account_number"] = str(account_number).strip().replace(" ", "")
        payment["account_name"] = str(account_name).strip().upper()
        self.save()
        return True, "Cập nhật thông tin ngân hàng thành công."

    # API Tokens
    def get_api_tokens(self):
        return self.get_data().get("api_tokens", {})

    def get_token_sets(self):
        return self.get_api_tokens().get("token_sets", [])

    def get_token_sets_summaries(self):
        sets = self.get_token_sets()
        return [get_token_summary(t) for t in sets]

    def get_active_token_sets(self):
        sets = self.get_token_sets()
        active = [t for t in sets if t.get("active", True)]
        target_list = active if active else sets

        def sort_priority(t):
            st = t.get("test_status")
            summ = get_token_summary(t)
            is_exp = summ.get("is_expired", False)
            if st == "200_OK":
                return 0 if not is_exp else 1
            elif not st:
                return 2
            else:
                return 3

        return sorted(target_list, key=sort_priority)

    def add_token_set(self, token_data):
        """Add a new token set to the top of token_sets."""
        if not token_data.get("fetch_token") or not token_data.get("app_transaction"):
            return False, "fetch_token và app_transaction là bắt buộc."

        # Sanitize whitespace / line breaks
        token_data["fetch_token"] = re.sub(r"[\s\r\n]+", "", str(token_data["fetch_token"]))
        token_data["app_transaction"] = re.sub(r"[\s\r\n]+", "", str(token_data["app_transaction"]))

        # Auto-detect inverted tokens
        ft_p = decode_jwt_payload(token_data["fetch_token"]) or {}
        at_p = decode_jwt_payload(token_data["app_transaction"]) or {}
        if "receiptType" in ft_p and "transactionId" in at_p:
            token_data["fetch_token"], token_data["app_transaction"] = token_data["app_transaction"], token_data["fetch_token"]

        if not token_data.get("id"):
            token_data["id"] = f"token_{int(time.time())}"
        if not token_data.get("name"):
            token_data["name"] = f"Token {datetime.now().strftime('%d/%m %H:%M')}"
        if "active" not in token_data:
            token_data["active"] = True
        if not token_data.get("created_at"):
            token_data["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        token_sets = self.get_data().setdefault("api_tokens", {}).setdefault("token_sets", [])
        # Prepend to the beginning
        token_sets.insert(0, token_data)
        # Limit max 30 tokens
        self.get_data()["api_tokens"]["token_sets"] = token_sets[:30]
        self.save()
        return True, "Thêm bộ token thành công."

    def update_token_set(self, token_id, update_data):
        token_sets = self.get_token_sets()
        for t in token_sets:
            if t.get("id") == token_id:
                for k, v in update_data.items():
                    if k in ("fetch_token", "app_transaction") and v:
                        t[k] = re.sub(r"[\s\r\n]+", "", str(v))
                    else:
                        t[k] = v
                self.save()
                return True, "Cập nhật token thành công."
        return False, "Không tìm thấy token."

    def toggle_token_set(self, token_id):
        token_sets = self.get_token_sets()
        for t in token_sets:
            if t.get("id") == token_id:
                t["active"] = not t.get("active", True)
                self.save()
                return True, t["active"]
        return False, "Không tìm thấy token."

    def delete_token_set(self, token_id):
        token_sets = self.get_token_sets()
        new_sets = [t for t in token_sets if t.get("id") != token_id]
        if len(new_sets) == len(token_sets):
            return False, "Không tìm thấy token để xóa."
        self.get_data()["api_tokens"]["token_sets"] = new_sets
        self.save()
        return True, "Đã xóa bộ token."

    def set_revenuecat_bearer(self, bearer_str):
        bearer_str = str(bearer_str or "").strip()
        if bearer_str and not bearer_str.lower().startswith("bearer "):
            bearer_str = f"Bearer {bearer_str}"
        self.get_data().setdefault("api_tokens", {})["revenuecat_bearer"] = bearer_str
        self.save()
        return True, "Cập nhật RevenueCat bearer thành công."

    def set_firebase_appcheck(self, token_str):
        self.get_data().setdefault("api_tokens", {})["firebase_appcheck"] = str(token_str).strip()
        self.save()
        return True, "Cập nhật Firebase AppCheck token thành công."

    def set_firebase_instance_id_token(self, token_str):
        self.get_data().setdefault("api_tokens", {})["firebase_instance_id_token"] = str(token_str).strip()
        self.save()
        return True, "Cập nhật Firebase Instance ID token thành công."

    def set_locket_bearer(self, token_str):
        bearer = str(token_str).strip()
        if bearer and not bearer.lower().startswith("bearer "):
            bearer = f"Bearer {bearer}"
        self.get_data().setdefault("api_tokens", {})["locket_bearer"] = bearer
        self.save()
        return True, "Cập nhật Locket Bearer token thành công."

    def set_locket_refresh_token(self, token_str):
        self.get_data().setdefault("api_tokens", {})["locket_refresh_token"] = str(token_str).strip()
        self.save()
        return True, "Cập nhật Locket Refresh token thành công."

    def refresh_locket_token(self):
        rf_token = self.get_data().get("api_tokens", {}).get("locket_refresh_token")
        if not rf_token:
            return None
        try:
            import requests
            url = "https://securetoken.googleapis.com/v1/token?key=AIzaSyCQngaaXQIfJaH0aS2l7REgIjD7nL431So"
            headers = {
                "X-Ios-Bundle-Identifier": "com.locket.Locket",
                "User-Agent": "Locket/2283 CFNetwork/3896.100.1.2.1 Darwin/27.0.0"
            }
            res = requests.post(
                url,
                headers=headers,
                data={"grant_type": "refresh_token", "refresh_token": rf_token},
                timeout=8
            )
            if res.ok:
                data = res.json()
                new_id_token = data.get("id_token")
                new_refresh = data.get("refresh_token")
                if new_id_token:
                    self.set_locket_bearer(new_id_token)
                if new_refresh:
                    self.set_locket_refresh_token(new_refresh)
                return new_id_token
        except Exception as e:
            print(f"[refresh_locket_token] Error: {e}")
        return None

    # Telegram
    def get_telegram_config(self):
        return self.get_data().get("telegram", {})

    def update_telegram(self, bot_token, chat_id):
        tg = self.get_data().setdefault("telegram", {})
        tg["bot_token"] = str(bot_token).strip()
        tg["chat_id"] = str(chat_id).strip()
        self.save()
        return True, "Cập nhật Telegram thành công."


# Singleton instance
config_manager = ConfigManager()
