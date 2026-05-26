#!/usr/bin/env python3
"""
SecureShare - اشتراک‌گذاری امن فایل در شبکه محلی
"""

import os
import sys
import ssl
import json
import time
import hashlib
import secrets
import logging
import ipaddress
import mimetypes
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import quote, unquote, parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime as dt

# ============ تنظیمات ============
CONFIG_FILE = "config.json"
DEFAULT_PASSWORD = "admin123"

CONFIG = {
    "host": "0.0.0.0",
    "port": 8443,
    "share_dir": "./shared_files",
    "cert_file": "./certs/server.crt",
    "key_file": "./certs/server.key",
    "max_login_attempts": 5,
    "lockout_time": 300,
    "session_timeout": 3600,
    "max_file_size": 2147483648,
    "password_hash": None
}

sessions = {}
sessions_lock = threading.Lock()
login_attempts = {}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('access.log'),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ============ توابع ============
def get_password_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            loaded = json.load(f)
            CONFIG.update(loaded)
    if CONFIG["password_hash"] is None:
        CONFIG["password_hash"] = get_password_hash(DEFAULT_PASSWORD)
        save_config()

def save_config():
    with open(CONFIG_FILE, 'w') as f:
        json.dump({k: v for k, v in CONFIG.items() if k not in ["host"]}, f, indent=2)

def change_password():
    new_pass = input("رمز عبور جدید را وارد کنید (حداقل 8 کاراکتر): ").strip()
    if len(new_pass) < 8:
        print("رمز عبور باید حداقل 8 کاراکتر باشد!")
        return
    confirm = input("تکرار رمز عبور: ").strip()
    if new_pass != confirm:
        print("رمزها مطابقت ندارند!")
        return
    CONFIG["password_hash"] = get_password_hash(new_pass)
    save_config()
    print("رمز عبور با موفقیت تغییر کرد!")

def generate_cert():
    cert_dir = Path("./certs")
    cert_dir.mkdir(exist_ok=True)
    cert_file = cert_dir / "server.crt"
    key_file = cert_dir / "server.key"
    
    if cert_file.exists() and key_file.exists():
        return
    
    print("در حال تولید گواهی SSL...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tehran"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tehran"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureShare"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        dt.datetime.now(dt.timezone.utc)
    ).not_valid_after(
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.DNSName(u"*.local"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("گواهی SSL با موفقیت تولید شد!")

def is_lan_ip(ip: str) -> bool:
    if ip == "127.0.0.1" or ip == "::1":
        return True
    try:
        addr = ipaddress.ip_address(ip)
        private_nets = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        ]
        return any(addr in net for net in private_nets)
    except:
        return False

def create_session(ip: str) -> str:
    token = secrets.token_urlsafe(32)
    with sessions_lock:
        sessions[token] = {
            "ip": ip,
            "created": time.time(),
            "last_active": time.time()
        }
    return token

def validate_session(token: str, ip: str) -> bool:
    with sessions_lock:
        if token not in sessions:
            return False
        s = sessions[token]
        if s["ip"] != ip:
            return False
        if time.time() - s["last_active"] > CONFIG["session_timeout"]:
            del sessions[token]
            return False
        s["last_active"] = time.time()
    return True

def is_locked_out(ip: str) -> bool:
    if ip not in login_attempts:
        return False
    a = login_attempts[ip]
    if a.get("locked_until", 0) > time.time():
        return True
    if a.get("locked_until", 0) > 0 and a["locked_until"] <= time.time():
        login_attempts[ip] = {"count": 0}
    return False

def record_failed_login(ip: str):
    if ip not in login_attempts:
        login_attempts[ip] = {"count": 0}
    login_attempts[ip]["count"] += 1
    if login_attempts[ip]["count"] >= CONFIG["max_login_attempts"]:
        login_attempts[ip]["locked_until"] = time.time() + CONFIG["lockout_time"]
        log.warning(f"IP {ip} به مدت {CONFIG['lockout_time']} ثانیه قفل شد")

def reset_login_attempts(ip: str):
    login_attempts.pop(ip, None)

def safe_path(base: str, rel: str):
    base_path = Path(base).resolve()
    try:
        target = (base_path / unquote(rel)).resolve()
        if base_path in target.parents or target == base_path:
            return target
        return None
    except:
        return None

def file_icon(name: str) -> str:
    ext = Path(name).suffix.lower()
    icons = {
        'pdf': '📄', 'doc': '📘', 'docx': '📘', 'xls': '📗', 'xlsx': '📗',
        'ppt': '📙', 'pptx': '📙', 'txt': '📝', 'md': '📝', 'jpg': '🖼️',
        'jpeg': '🖼️', 'png': '🖼️', 'gif': '🎬', 'mp4': '🎥', 'mp3': '🎵',
        'zip': '📦', 'rar': '📦', 'py': '🐍', 'js': '📜', 'html': '🌐',
        'css': '🎨', 'exe': '⚙️',
    }
    return icons.get(ext, '📁')

def fmt_size(b: int) -> str:
    for u in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

# ============ HTML ============
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureShare</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Vazirmatn', Tahoma, sans-serif;
            background: #0a0e1a;
            color: #e2e8f0;
            min-height: 100vh;
            direction: rtl;
        }
        .login-wrap {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(ellipse at 50% 0%, rgba(59,130,246,0.08) 0%, transparent 70%);
        }
        .login-box {
            background: #111827;
            border: 1px solid #1e2d45;
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 380px;
            box-shadow: 0 0 20px rgba(59,130,246,0.15);
        }
        .login-logo { text-align: center; margin-bottom: 32px; }
        .login-logo .icon { font-size: 48px; margin-bottom: 8px; }
        .login-logo h1 { font-size: 22px; font-weight: 700; color: #60a5fa; }
        .form-group { margin-bottom: 18px; }
        .form-group label { display: block; font-size: 13px; color: #64748b; margin-bottom: 5px; }
        .form-group input {
            width: 100%;
            background: #1a2235;
            border: 1px solid #1e2d45;
            border-radius: 8px;
            padding: 12px 14px;
            color: #e2e8f0;
            font-size: 14px;
            direction: ltr;
            text-align: right;
        }
        .form-group input:focus { outline: none; border-color: #3b82f6; }
        .btn {
            width: 100%;
            padding: 12px;
            background: #3b82f6;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
        }
        .btn:hover { background: #60a5fa; }
        .error-msg {
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.3);
            color: #ef4444;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13px;
            margin-bottom: 16px;
            text-align: center;
        }
        .app { display: flex; flex-direction: column; min-height: 100vh; }
        .topbar {
            background: #111827;
            border-bottom: 1px solid #1e2d45;
            padding: 14px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .topbar-logo { font-weight: 700; font-size: 18px; }
        .topbar-actions { display: flex; gap: 10px; align-items: center; }
        .badge {
            background: rgba(34,197,94,0.15);
            color: #22c55e;
            border: 1px solid rgba(34,197,94,0.3);
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
        }
        .btn-sm {
            padding: 7px 14px;
            font-size: 13px;
            background: #1a2235;
            border: 1px solid #1e2d45;
            color: #e2e8f0;
            border-radius: 7px;
            cursor: pointer;
        }
        .btn-sm:hover { border-color: #3b82f6; color: #60a5fa; }
        .btn-danger { border-color: rgba(239,68,68,0.3); color: #ef4444; }
        .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
        .upload-zone {
            border: 2px dashed #1e2d45;
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            cursor: pointer;
            margin-bottom: 24px;
        }
        .upload-zone:hover { border-color: #3b82f6; background: rgba(59,130,246,0.05); }
        .upload-zone.drag { border-color: #3b82f6; background: rgba(59,130,246,0.1); }
        #file-input { display: none; }
        .upload-progress {
            background: #111827;
            border: 1px solid #1e2d45;
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 10px;
            display: none;
        }
        .prog-name { font-size: 13px; margin-bottom: 8px; display: flex; justify-content: space-between; }
        .prog-bar-wrap { background: #1a2235; border-radius: 4px; height: 6px; overflow: hidden; }
        .prog-bar { height: 100%; background: #3b82f6; border-radius: 4px; width: 0%; }
        .file-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
        }
        .file-card {
            background: #111827;
            border: 1px solid #1e2d45;
            border-radius: 10px;
            padding: 14px 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .file-card:hover { border-color: #3b82f6; }
        .file-icon { font-size: 28px; flex-shrink: 0; }
        .file-info { flex: 1; min-width: 0; }
        .file-name { font-size: 14px; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .file-meta { font-size: 11px; color: #64748b; margin-top: 3px; }
        .file-actions { display: flex; gap: 6px; flex-shrink: 0; }
        .icon-btn {
            background: #1a2235;
            border: 1px solid #1e2d45;
            color: #64748b;
            width: 30px;
            height: 30px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
        }
        .icon-btn:hover { color: #e2e8f0; border-color: #3b82f6; }
        .empty-state { text-align: center; padding: 60px 20px; color: #64748b; }
        .toast {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%) translateY(20px);
            background: #111827;
            border: 1px solid #1e2d45;
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 14px;
            opacity: 0;
            transition: all 0.3s;
            z-index: 9999;
        }
        .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
        .toast.success { border-color: #22c55e; color: #22c55e; }
        .toast.error { border-color: #ef4444; color: #ef4444; }
    </style>
</head>
<body>
    {BODY_CONTENT}
    <div id="toast" class="toast"></div>
</body>
</html>
'''

def render_login(error=""):
    err_html = f'<div class="error-msg">{error}</div>' if error else ''
    body = f'''
    <div class="login-wrap">
        <div class="login-box">
            <div class="login-logo">
                <div class="icon">🔒</div>
                <h1>SecureShare</h1>
            </div>
            {err_html}
            <div class="form-group">
                <label>رمز عبور</label>
                <input type="password" id="pwd" placeholder="رمز عبور را وارد کنید">
            </div>
            <button class="btn" onclick="doLogin()">ورود</button>
        </div>
    </div>
    <script>
        document.getElementById('pwd').addEventListener('keydown', e => {{ if(e.key==='Enter') doLogin(); }});
        function doLogin() {{
            const pwd = document.getElementById('pwd').value;
            fetch('/login', {{method:'POST', headers:{{"Content-Type":"application/json"}}, body:JSON.stringify({{password:pwd}})}})
                .then(r=>r.json())
                .then(d=>{{ if(d.ok) location.reload(); else location.reload(); }});
        }}
    </script>
    '''
    return HTML_TEMPLATE.replace("{BODY_CONTENT}", body)

def render_app(files):
    cards = ""
    if files:
        for f in sorted(files, key=lambda x: x['mtime'], reverse=True):
            enc_name = quote(f['name'])
            cards += f'''
            <div class="file-card">
                <div class="file-icon">{file_icon(f['name'])}</div>
                <div class="file-info">
                    <div class="file-name">{f['name']}</div>
                    <div class="file-meta">{fmt_size(f['size'])} • {f['date']}</div>
                </div>
                <div class="file-actions">
                    <a href="/download?name={enc_name}" class="icon-btn">⬇️</a>
                    <button class="icon-btn" onclick="deleteFile('{enc_name}')">🗑️</button>
                </div>
            </div>'''
    else:
        cards = '<div class="empty-state">📂 هیچ فایلی وجود ندارد</div>'
    
    body = f'''
    <div class="app">
        <div class="topbar">
            <div class="topbar-logo">🔒 SecureShare</div>
            <div class="topbar-actions">
                <span class="badge">🛡️ امن</span>
                <span>{len(files)} فایل</span>
                <button class="btn-sm btn-danger" onclick="logout()">خروج</button>
            </div>
        </div>
        <div class="container">
            <div class="upload-zone" id="drop-zone">
                <div>📤</div>
                <p><strong>فایل را اینجا رها کنید</strong></p>
                <input type="file" id="file-input" multiple>
            </div>
            <div class="upload-progress" id="upload-progress">
                <div class="prog-name"><span id="prog-name">در حال آپلود...</span><span id="prog-pct">0%</span></div>
                <div class="prog-bar-wrap"><div class="prog-bar" id="prog-bar"></div></div>
            </div>
            <div class="file-grid">{cards}</div>
        </div>
    </div>
    <script>
        function logout() {{ fetch('/logout', {{method:'POST'}}).then(() => location.reload()); }}
        function deleteFile(name) {{
            if(!confirm('حذف فایل؟')) return;
            fetch('/delete?name=' + encodeURIComponent(name), {{method:'DELETE'}})
                .then(r => {{ if(r.ok) location.reload(); else alert('خطا'); }});
        }}
        function showToast(msg, type) {{
            var t = document.getElementById('toast');
            t.textContent = msg;
            t.className = 'toast ' + type;
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 3000);
        }}
        var zone = document.getElementById('drop-zone');
        if(zone) {{
            zone.addEventListener('dragover', e => {{ e.preventDefault(); zone.classList.add('drag'); }});
            zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
            zone.addEventListener('drop', e => {{
                e.preventDefault();
                zone.classList.remove('drag');
                var files = e.dataTransfer.files;
                if(files.length) uploadFiles(files);
            }});
            zone.addEventListener('click', () => document.getElementById('file-input').click());
            document.getElementById('file-input').addEventListener('change', e => {{
                if(e.target.files.length) uploadFiles(e.target.files);
            }});
        }}
        function uploadFiles(files) {{
            Array.from(files).forEach(file => uploadFile(file));
        }}
        function uploadFile(file) {{
            var prog = document.getElementById('upload-progress');
            if(prog) prog.style.display = 'block';
            var progName = document.getElementById('prog-name');
            var progBar = document.getElementById('prog-bar');
            var progPct = document.getElementById('prog-pct');
            if(progName) progName.textContent = file.name;
            var fd = new FormData();
            fd.append('file', file);
            var xhr = new XMLHttpRequest();
            xhr.upload.addEventListener('progress', e => {{
                if(e.lengthComputable) {{
                    var pct = Math.round(e.loaded / e.total * 100);
                    if(progBar) progBar.style.width = pct + '%';
                    if(progPct) progPct.textContent = pct + '%';
                }}
            }});
            xhr.addEventListener('load', () => {{
                if(xhr.status === 200) {{
                    showToast('آپلود شد', 'success');
                    setTimeout(() => location.reload(), 800);
                }} else {{
                    showToast('خطا', 'error');
                    if(prog) prog.style.display = 'none';
                }}
            }});
            xhr.open('POST', '/upload');
            xhr.send(fd);
        }}
    </script>
    '''
    return HTML_TEMPLATE.replace("{BODY_CONTENT}", body)

# ============ Handler ============
class SecureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def get_client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]
    
    def get_session_token(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                return part[8:]
        return None
    
    def is_authenticated(self):
        token = self.get_session_token()
        if not token:
            return False
        return validate_session(token, self.get_client_ip())
    
    def send_html(self, content, status=200):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(data))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
    
    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)
    
    def send_redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()
    
    def block_non_lan(self):
        ip = self.get_client_ip()
        if not is_lan_ip(ip):
            log.warning(f"دسترسی غیرمجاز از IP: {ip}")
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"403 Forbidden - LAN Only")
            return True
        return False
    
    def do_GET(self):
        if self.block_non_lan():
            return
        
        ip = self.get_client_ip()
        path = self.path.split("?")[0]
        
        if path == "/" or path == "":
            if not self.is_authenticated():
                self.send_html(render_login())
                return
            
            share_dir = Path(CONFIG["share_dir"])
            share_dir.mkdir(exist_ok=True)
            files = []
            for f in share_dir.iterdir():
                if f.is_file():
                    st = f.stat()
                    files.append({
                        "name": f.name,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "date": datetime.fromtimestamp(st.st_mtime).strftime("%Y/%m/%d %H:%M")
                    })
            self.send_html(render_app(files))
        
        elif path == "/download":
            if not self.is_authenticated():
                self.send_redirect("/")
                return
            
            params = parse_qs(urlparse(self.path).query)
            name = params.get("name", [""])[0]
            file_path = safe_path(CONFIG["share_dir"], name)
            
            if not file_path or not file_path.is_file():
                self.send_response(404)
                self.end_headers()
                return
            
            mime, _ = mimetypes.guess_type(str(file_path))
            mime = mime or "application/octet-stream"
            size = file_path.stat().st_size
            
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", size)
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.end_headers()
            
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.block_non_lan():
            return
        
        ip = self.get_client_ip()
        path = self.path.split("?")[0]
        
        if path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            try:
                data = json.loads(body)
                password = data.get("password", "")
            except:
                self.send_json({"ok": False})
                return
            
            if is_locked_out(ip):
                self.send_json({"ok": False})
                return
            
            if hashlib.sha256(password.encode()).hexdigest() == CONFIG["password_hash"]:
                reset_login_attempts(ip)
                token = create_session(ip)
                log.info(f"ورود موفق - IP: {ip}")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
            else:
                record_failed_login(ip)
                self.send_json({"ok": False})
        
        elif path == "/logout":
            token = self.get_session_token()
            if token:
                with sessions_lock:
                    sessions.pop(token, None)
            self.send_response(200)
            self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")
            self.end_headers()
        
        elif path == "/upload":
            if not self.is_authenticated():
                self.send_json({"ok": False}, 401)
                return
            
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type:
                self.send_json({"ok": False}, 400)
                return
            
            boundary = content_type.split("boundary=")[-1].encode()
            length = int(self.headers.get("Content-Length", 0))
            
            if length > CONFIG["max_file_size"]:
                self.send_json({"ok": False, "error": "فایل خیلی بزرگ است"}, 413)
                return
            
            body = self.rfile.read(length)
            parts = body.split(b"--" + boundary)
            
            for part in parts[1:-1]:
                if b"\r\n\r\n" not in part:
                    continue
                headers_raw, content = part.split(b"\r\n\r\n", 1)
                if content.endswith(b"\r\n"):
                    content = content[:-2]
                headers_str = headers_raw.decode("utf-8", errors="ignore")
                
                if 'filename="' not in headers_str:
                    continue
                
                filename = headers_str.split('filename="')[1].split('"')[0]
                filename = Path(filename).name
                
                if not filename:
                    continue
                
                share_dir = Path(CONFIG["share_dir"])
                share_dir.mkdir(exist_ok=True)
                dest = share_dir / filename
                
                if dest.exists():
                    stem = dest.stem
                    suffix = dest.suffix
                    i = 1
                    while dest.exists():
                        dest = share_dir / f"{stem}_{i}{suffix}"
                        i += 1
                
                with open(dest, "wb") as f:
                    f.write(content)
                
                log.info(f"آپلود فایل: {filename} - IP: {ip}")
            
            self.send_json({"ok": True})
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_DELETE(self):
        if self.block_non_lan():
            return
        
        if not self.is_authenticated():
            self.send_response(401)
            self.end_headers()
            return
        
        params = parse_qs(urlparse(self.path).query)
        name = params.get("name", [""])[0]
        file_path = safe_path(CONFIG["share_dir"], name)
        
        if file_path and file_path.is_file():
            os.remove(file_path)
            log.info(f"حذف فایل: {name} - IP: {self.get_client_ip()}")
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

def get_local_ips():
    import socket
    ips = []
    try:
        hostname = socket.gethostname()
        ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list(set(i[4][0] for i in ips if not i[4][0].startswith("127.")))
    except:
        pass
    return ips if ips else ["127.0.0.1"]

def main():
    load_config()
    Path(CONFIG["share_dir"]).mkdir(exist_ok=True)
    
    if "--change-password" in sys.argv:
        change_password()
        return
    
    if "--set-password" in sys.argv:
        idx = sys.argv.index("--set-password")
        if idx + 1 < len(sys.argv):
            new_pass = sys.argv[idx + 1]
            CONFIG["password_hash"] = get_password_hash(new_pass)
            save_config()
            print("رمز عبور با موفقیت تغییر کرد!")
        return
    
    generate_cert()
    
    server = HTTPServer((CONFIG["host"], CONFIG["port"]), SecureHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CONFIG["cert_file"], CONFIG["key_file"])
    # اصلاح خطا: server_only -> server_side=True
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    
    ips = get_local_ips()
    port = CONFIG["port"]
    
    print("\n" + "="*50)
    print("SecureShare - سرور امن اشتراک فایل")
    print("="*50)
    for ip in ips:
        print(f"آدرس: https://{ip}:{port}")
    print(f"پوشه فایل‌ها: {Path(CONFIG['share_dir']).resolve()}")
    print(f"رمز پیش‌فرض: {DEFAULT_PASSWORD}")
    print("برای تغییر رمز: python server.py --change-password")
    print("="*50)
    print("برای توقف: Ctrl+C\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nسرور متوقف شد")

if __name__ == "__main__":
    main()