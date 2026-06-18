from flask import Flask, request, render_template, jsonify, session, make_response, Response
import os, re, glob, base64, json, secrets, time, hashlib, threading, tempfile, shutil
from collections import OrderedDict
from functools import wraps
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFont
import io
import random
import string

load_dotenv()
app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=360)

CAPTCHA_DEFAULTS = {
    "width": 320,
    "height": 120,
    "channels": 3,
    "loop_frames": 30,
    "scroll_speed": 2,
    "font_size": 75,
    "captcha_length": 5,
    "allowed_chars": "23456789ABCDEFGHJKLMNPRSTXYZ"
}

# === ReDoS 防护 ===
import concurrent.futures

_REDOS_DANGEROUS_PATTERNS = [
    re.compile(r'\([^)]*[+*][^)]*\)[+*]'),
    re.compile(r'\([^)]*\|[^)]*\)[+*]'),
    re.compile(r'\(\.\+\)\+'),
    re.compile(r'\(\.\*\)\*'),
    re.compile(r'\(\.\*\)\{\d+,?\}'),
    re.compile(r'\(\\[wWdDsS]\+\)\+'),
    re.compile(r'\(\\[wWdDsS]\*\)\*'),
]

REGEX_TIMEOUT = 1.0
REGEX_CONTENT_MAX = 1024

def _is_redos_dangerous(pattern: str) -> bool:
    stripped = re.sub(r'\\.', '', pattern)
    for pat in _REDOS_DANGEROUS_PATTERNS:
        if pat.search(stripped):
            return True
    depth = 0
    max_depth = 0
    for ch in stripped:
        if ch == '(':
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch == ')':
            depth -= 1
    if max_depth > 3:
        return True
    return False

def safe_regex_search(pattern: str, content: str, timeout: float = REGEX_TIMEOUT) -> bool:
    content = content[:REGEX_CONTENT_MAX]
    def _do_search():
        try:
            return bool(re.search(pattern, content))
        except re.error:
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_do_search)
        try:
            return future.result(timeout=timeout)
        except (concurrent.futures.TimeoutError, Exception):
            return False

# === 1. 密钥与会话安全配置 ===
SECRET_KEY_ENV = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY_ENV:
    raise RuntimeError('FLASK_SECRET_KEY 未设置！请在 .env 文件中配置 FLASK_SECRET_KEY')
app.secret_key = SECRET_KEY_ENV

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024

CST = timezone(timedelta(hours=8))

# === 2. 可信代理配置 ===
TRUSTED_PROXIES = [ip.strip() for ip in os.environ.get('TRUSTED_PROXIES', '').split(',') if ip.strip()]

# === 3. 路径与初始化 ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MSG_DIR = os.path.join(DATA_DIR, '留言')
REPLY_DIR = os.path.join(DATA_DIR, '回复')
QUN_DIR = os.path.join(DATA_DIR, '群')
VOTE_DIR = os.path.join(DATA_DIR, 'vote_data')
IP_DIR = os.path.join(DATA_DIR, 'ip')
RSA_PUB = os.path.join(BASE_DIR, 'gongyao.txt')
UNDER_FILE = os.path.join(DATA_DIR, 'under.txt')
CHAT_FILE = os.path.join(DATA_DIR, 'chat_data.json')
RULE_FILE = os.path.join(QUN_DIR, 'rule.txt')
THRESHOLD_FILE = os.path.join(QUN_DIR, 'threshold.txt')
NOTICE_FILE = os.path.join(DATA_DIR, 'notice_data.json')
PERM_FILE = os.path.join(QUN_DIR, 'permission.txt')
BLACK_FILE = os.path.join(DATA_DIR, 'black.txt')
WHITE_FILE = os.path.join(DATA_DIR, 'white.txt')
LOG_FILE = os.path.join(DATA_DIR, 'log.txt')
CHAT_DIR = os.path.join(DATA_DIR, 'chat')
REPORT_DIR = os.path.join(DATA_DIR, 'chat_reports')
CHAT_RETENTION_FILE = os.path.join(CHAT_DIR, 'retention_hours.txt')

for d in [MSG_DIR, REPLY_DIR, QUN_DIR, VOTE_DIR, IP_DIR, CHAT_DIR, REPORT_DIR]:
    os.makedirs(d, exist_ok=True)
_ip_log_lock = threading.Lock()
for f, v in [
    (UNDER_FILE, 'under construction'),
    (PERM_FILE, '0'),
    (BLACK_FILE, ''),
    (WHITE_FILE, ''),
    (RULE_FILE, ''),
    (THRESHOLD_FILE, '5')
]:
    if not os.path.exists(f):
        open(f, 'w', encoding='utf-8').write(v)
if not os.path.exists(CHAT_FILE):
    json.dump([], open(CHAT_FILE, 'w', encoding='utf-8'))
if not os.path.exists(NOTICE_FILE):
    json.dump([], open(NOTICE_FILE, 'w', encoding='utf-8'))
if not os.path.exists(CHAT_RETENTION_FILE):
    open(CHAT_RETENTION_FILE, 'w', encoding='utf-8').write('0')
# === 4. 并发安全工具 ===
_file_lock = threading.Lock()

def atomic_write(path, content):
    dir_name = os.path.dirname(path) or '.'
    with _file_lock:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
        try:
            if isinstance(content, str):
                os.write(fd, content.encode('utf-8'))
            else:
                os.write(fd, content)
            os.close(fd)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

def get_seq():
    with _file_lock:
        return get_seq_unlocked()

def get_seq_unlocked():
    files = glob.glob(os.path.join(MSG_DIR, '留言_*.txt'))
    seqs = [int(m.group(1)) for f in files if (m := re.search(r'(\d+)', os.path.basename(f)))]
    return max(seqs) + 1 if seqs else 1

def atomic_write_unlocked(path, content):
    dir_name = os.path.dirname(path) or '.'
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
    try:
        if isinstance(content, str):
            os.write(fd, content.encode('utf-8'))
        else:
            os.write(fd, content)
        os.close(fd)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

def atomic_chat_update(updater_fn):
    with _file_lock:
        with open(CHAT_FILE, 'r', encoding='utf-8') as f:
            chat = json.load(f)
        result = updater_fn(chat)
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(CHAT_FILE), suffix='.tmp')
        try:
            os.write(fd, json.dumps(chat, ensure_ascii=False).encode('utf-8'))
            os.close(fd)
            os.replace(tmp_path, CHAT_FILE)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
        return result

def safe_resolve(base_dir, filename):
    safe = re.sub(r'[^\w.\-]', '', filename)
    if not safe or safe in ('.', '..'):
        return None
    full = os.path.realpath(os.path.join(base_dir, safe))
    base = os.path.realpath(base_dir)
    if not full.startswith(base + os.sep) and full != base:
        return None
    return full

def read_perm_file():
    with _file_lock:
        try:
            with open(PERM_FILE, 'r') as f:
                return f.read().strip()
        except Exception:
            return '0'

def safe_vote_dir(poll_id):
    safe = re.sub(r'[^\w\u4e00-\u9fff\-]', '_', poll_id)
    if not safe or safe in ('.', '..'):
        return None
    full = os.path.realpath(os.path.join(VOTE_DIR, safe))
    base = os.path.realpath(VOTE_DIR)
    if not full.startswith(base + os.sep) and full != base:
        return None
    return full

def get_vote_seq_unlocked(poll_dir):
    files = glob.glob(os.path.join(poll_dir, '投票_*.txt'))
    seqs = [int(m.group(1)) for f in files if (m := re.search(r'(\d+)', os.path.basename(f)))]
    return max(seqs) + 1 if seqs else 1

def get_vote_seq(poll_dir):
    with _file_lock:
        return get_vote_seq_unlocked(poll_dir)

# === 4.5 Origin/Referer 校验（防御 CSRF 固定 Token + 跨站伪造） ===
import urllib.parse as _urlparse

FORCE_HOST = os.environ.get('FORCE_HOST', '').strip()

def _extract_host_parts(url):
    """从 URL 中安全提取 netloc 和 hostname"""
    try:
        p = _urlparse.urlparse(url)
        return p.netloc, p.hostname
    except Exception:
        return None, None


def _build_allowed_hosts():
    """构建允许的 Host 集合（包含当前请求 Host + 环境变量 + 本地回环）"""
    allowed = set()
    # 1. 环境变量 FORCE_HOST（若设置则优先）
    if FORCE_HOST:
        allowed.add(FORCE_HOST)
        allowed.add(FORCE_HOST.split(':')[0])
    # 2. 当前请求的 Host（同源请求）
    host = request.host
    if host:
        allowed.add(host)
        allowed.add(host.split(':')[0])
    # 3. 本地回环（开发/内网）
    port = request.environ.get('SERVER_PORT', '5033')
    for lh in ('127.0.0.1', 'localhost', '::1'):
        allowed.add(lh)
        allowed.add(f'{lh}:{port}')
    return allowed

def validate_origin_referer():
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
        return True
    origin = request.headers.get('Origin') or ''
    referer = request.headers.get('Referer') or ''
    # 必须至少有一个来源头（防止非浏览器伪造）
    if not origin and not referer:
        return False
    allowed = _build_allowed_hosts()
    if origin:
        netloc, hostname = _extract_host_parts(origin)
        if netloc and netloc not in allowed:
            if hostname and hostname not in allowed:
                return False
    if referer:
        netloc, hostname = _extract_host_parts(referer)
        if netloc and netloc not in allowed:
            if hostname and hostname not in allowed:
                return False
    return True

def require_csrf(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            # ★ 第一层：Origin / Referer 校验（防跨站伪造）
            if not validate_origin_referer():
                return jsonify({'error': '跨域请求被拒绝（Origin/Referer 不匹配）'}), 403
            # ★ 第二层：CSRF Token 校验（防同站利用）
            token = session.get('csrf_token')
            header = request.headers.get('X-CSRF-Token')
            if not token or token != header:
                return jsonify({'error': 'CSRF 校验失败'}), 403
        return f(*args, **kwargs)
    return decorated

def require_private_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_has_key'):
            return jsonify({'error': '私钥未校验'}), 403
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════════
# 4.6 CAPTCHA 人机验证模块（动态 GIF 验证码）
# ═══════════════════════════════════════════════════════════
import random as _captcha_random
import hashlib as _captcha_hash
import secrets as _captcha_secrets
import time as _captcha_time
import json as _captcha_json
import threading as _captcha_threading
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import io

# ---------- 默认配置 ----------
CAPTCHA_DEFAULTS = {
    "width": 320,
    "height": 120,
    "channels": 3,
    "loop_frames": 30,
    "scroll_speed": 2,
    "font_size": 75,
    "captcha_length": 5,
    "allowed_chars": "23456789ABCDEFGHJKLMNPRSTXYZ"
}

# ---------- 路径 ----------
CAPTCHA_DIR = os.path.join(DATA_DIR, 'captcha')
os.makedirs(CAPTCHA_DIR, exist_ok=True)

CAPTCHA_CONFIG_FILE = os.path.join(CAPTCHA_DIR, 'config.json')
CAPTCHA_VERIFIED_FILE = os.path.join(CAPTCHA_DIR, 'verified.json')
CAPTCHA_CHALLENGES_FILE = os.path.join(CAPTCHA_DIR, 'challenges.json')
CAPTCHA_LOG_FILE = os.path.join(CAPTCHA_DIR, 'verified_log.json')

# 初始化文件
for f, default in [
    (CAPTCHA_CONFIG_FILE, {"enabled": True, "duration_minutes": 30}),
    (CAPTCHA_VERIFIED_FILE, {}),
    (CAPTCHA_CHALLENGES_FILE, {}),
    (CAPTCHA_LOG_FILE, []),
]:
    if not os.path.exists(f):
        atomic_write(f, _captcha_json.dumps(default, ensure_ascii=False))

_captcha_lock = _captcha_threading.Lock()

def _captcha_load_json(path):
    with _captcha_lock:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return _captcha_json.load(f)
        except Exception:
            return {}

def _captcha_save_json(path, data):
    atomic_write(path, _captcha_json.dumps(data, ensure_ascii=False))

# ---------- 配置读写 ----------
def get_captcha_config():
    config = _captcha_load_json(CAPTCHA_CONFIG_FILE)
    # 合并默认值
    for k, v in CAPTCHA_DEFAULTS.items():
        if k not in config:
            config[k] = v
    return config

def save_captcha_config(config):
    _captcha_save_json(CAPTCHA_CONFIG_FILE, config)

def get_verified_ips():
    return _captcha_load_json(CAPTCHA_VERIFIED_FILE)

def save_verified_ips(data):
    _captcha_save_json(CAPTCHA_VERIFIED_FILE, data)

def get_challenges():
    return _captcha_load_json(CAPTCHA_CHALLENGES_FILE)

def save_challenges(data):
    _captcha_save_json(CAPTCHA_CHALLENGES_FILE, data)

def get_verified_log():
    try:
        with open(CAPTCHA_LOG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def save_verified_log(data):
    atomic_write(CAPTCHA_LOG_FILE, json.dumps(data, ensure_ascii=False))

def get_aes_key():
    config = get_captcha_config()
    return config.get('aes_key', '')

# ---------- 清理 ----------
def _cleanup_challenges():
    challenges = get_challenges()
    now = _captcha_time.time()
    expired = [k for k, v in challenges.items() if v.get('expires_at', 0) < now]
    for k in expired:
        del challenges[k]
    if expired:
        save_challenges(challenges)

def _cleanup_verified():
    verified = get_verified_ips()
    now = _captcha_time.time()
    expired = [k for k, v in verified.items() if v < now]
    for k in expired:
        del verified[k]
    if expired:
        save_verified_ips(verified)

# ---------- 核心业务 ----------
def is_captcha_needed(ip):
    """检查IP是否需要验证"""
    if ip in load_whitelist():
        return False
    config = get_captcha_config()
    if not config.get('enabled', True):
        return False
    verified = get_verified_ips()
    if ip in verified and verified[ip] > _captcha_time.time():
        return False
    return True

def mark_captcha_verified(ip):
    config = get_captcha_config()
    duration = config.get('duration_minutes', 30)
    expiry = time.time() + duration * 60
    verified_at = time.time()

    verified = get_verified_ips()
    verified[ip] = expiry
    save_verified_ips(verified)

    # ★ 使用 RSA 加密存储日志
    plaintext = f"{ip}|{datetime.fromtimestamp(verified_at, CST).strftime('%Y-%m-%d %H:%M:%S')}|{datetime.fromtimestamp(expiry, CST).strftime('%Y-%m-%d %H:%M:%S')}"
    encrypted = rsa_encrypt_report(plaintext)   # 返回 "RSA:" + base64 或空字符串
    if encrypted:
        log = get_verified_log()
        log.append({'data': encrypted, 'ts': verified_at})
        if len(log) > 500:
            log = log[-500:]
        save_verified_log(log)

    return expiry

def require_captcha(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            ip = get_client_ip()
            if is_captcha_needed(ip):
                return jsonify({
                    "error": "captcha_required",
                    "message": "请先完成人机验证",
                    "captcha_url": "/captcha"
                }), 418
        return f(*args, **kwargs)
    return decorated

# ---------- GIF 生成 ----------
FONT_PATH = os.path.join(BASE_DIR, 'resources', 'MonaspaceNeon-WideBold.otf')
if not os.path.exists(FONT_PATH):
    FONT_PATH = None   # 降级使用默认字体

def _create_text_mask(text, font_size, offset, width, height):
    mask = np.zeros((height, width), dtype=bool)
    try:
        font = ImageFont.truetype(FONT_PATH, font_size) if FONT_PATH else ImageFont.load_default()
    except:
        font = ImageFont.load_default()
    img = Image.new('L', (width, height), 0)
    draw = ImageDraw.Draw(img)
    draw.text(offset, text, font=font, fill=255)
    text_layer = np.array(img)
    mask[text_layer > 128] = True
    return mask

def _generate_looping_noise(width, height, channels, loop_frames, scroll_speed):
    noise_height = loop_frames * scroll_speed
    noise = np.random.choice([0, 255], size=(noise_height, width), p=[0.5, 0.5]).astype(np.uint8)
    return np.stack([noise] * channels, axis=-1)

def _generate_frame(frame_index, text_mask, noise_texture, width, height, channels, scroll_speed):
    frame = np.zeros((height, width, channels), dtype=np.uint8)
    noise_height = noise_texture.shape[0]
    y_coords = np.arange(height).reshape(-1, 1)
    x_coords = np.arange(width).reshape(1, -1)
    text_offset = (frame_index * scroll_speed)
    bg_offset = -(frame_index * scroll_speed)
    text_noise_y = (y_coords + text_offset) % noise_height
    bg_noise_y = (y_coords + bg_offset) % noise_height
    text_pixels = noise_texture[text_noise_y, x_coords]
    bg_pixels = noise_texture[bg_noise_y, x_coords]
    frame[text_mask] = text_pixels[text_mask]
    frame[~text_mask] = bg_pixels[~text_mask]
    return frame

def generate_captcha_gif(text, config):
    w = config['width']
    h = config['height']
    channels = config['channels']
    loop_frames = config['loop_frames']
    speed = config['scroll_speed']
    font_size = config['font_size']
    offset = (15, 22)   # 可调整
    text_mask = _create_text_mask(text, font_size, offset, w, h)
    noise_texture = _generate_looping_noise(w, h, channels, loop_frames, speed)
    frames = [Image.fromarray(_generate_frame(i, text_mask, noise_texture, w, h, channels, speed)) for i in range(loop_frames)]
    gif_bytes = io.BytesIO()
    frames[0].save(gif_bytes, format='GIF', save_all=True, append_images=frames[1:], optimize=True, duration=40, loop=0)
    return gif_bytes.getvalue()

# ---------- 定时清理线程 ----------
def _captcha_cleanup_loop():
    while True:
        _captcha_time.sleep(60)
        try:
            _cleanup_challenges()
            _cleanup_verified()
        except Exception:
            pass

_captcha_thread = _captcha_threading.Thread(target=_captcha_cleanup_loop, daemon=True)
_captcha_thread.start()

# ---------- 前台路由 ----------
@app.route('/captcha')
def captcha_page():
    return render_template('captcha.html')

@app.route('/api/captcha/status', methods=['GET'])
def api_captcha_status():
    ip = get_client_ip()
    return jsonify({"captcha_needed": is_captcha_needed(ip)})

@app.route('/api/captcha/challenge', methods=['GET'])
def api_captcha_challenge():
    ip = get_client_ip()
    if not is_captcha_needed(ip):
        return jsonify({"captcha_needed": False})

    config = get_captcha_config()
    allowed_chars = config.get('allowed_chars', CAPTCHA_DEFAULTS['allowed_chars'])
    length = config.get('captcha_length', CAPTCHA_DEFAULTS['captcha_length'])
    text = ''.join(random.choices(allowed_chars, k=length))

    challenge_id = secrets.token_urlsafe(16)
    answer_hash = hashlib.sha256(text.encode()).hexdigest()
    challenges = get_challenges()
    challenges[challenge_id] = {
        'answer_hash': answer_hash,
        'expires_at': time.time() + 300,
        'ip': ip,
        'text': text   # 存储明文用于生成 GIF
    }
    save_challenges(challenges)
    return jsonify({
        'captcha_needed': True,
        'challenge_id': challenge_id,
        'expires_in': 300
    })

@app.route('/api/captcha.gif')
def api_captcha_gif():
    challenge_id = request.args.get('id')
    if not challenge_id:
        return "Missing ID", 400
    challenges = get_challenges()
    challenge = challenges.get(challenge_id)
    if not challenge or challenge.get('expires_at', 0) < time.time():
        return "Invalid or expired", 404
    config = get_captcha_config()
    gif_data = generate_captcha_gif(challenge['text'], config)
    return Response(gif_data, mimetype='image/gif')

@app.route('/api/captcha/verify', methods=['POST'])
def api_captcha_verify():
    data = request.get_json(silent=True) or {}
    challenge_id = data.get('challenge_id', '').strip()
    answer = data.get('answer', '').strip().upper()
    ip = get_client_ip()

    if not challenge_id or not answer:
        return jsonify({"success": False, "error": "参数不完整"}), 400

    _cleanup_challenges()
    challenges = get_challenges()
    challenge = challenges.get(challenge_id)
    if not challenge or challenge.get('expires_at', 0) < time.time():
        return jsonify({"success": False, "error": "验证码已过期"}), 400
    if challenge.get('ip') != ip:
        return jsonify({"success": False, "error": "挑战与IP不匹配"}), 403

    answer_hash = hashlib.sha256(answer.encode()).hexdigest()
    if answer_hash != challenge['answer_hash']:
        return jsonify({"success": False, "error": "答案错误"}), 400

    del challenges[challenge_id]
    save_challenges(challenges)

    expiry = mark_captcha_verified(ip)
    return jsonify({
        "success": True,
        "expires_at": expiry,
        "remaining_seconds": int(expiry - time.time())
    })

# ---------- 后台管理路由 ----------
@app.route('/admin/captcha')
def admin_captcha_page():
    return render_template('admin_captcha.html')

@app.route('/api/admin/captcha/config', methods=['GET', 'POST'])
@require_csrf
@require_private_key
def api_admin_captcha_config():
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    if request.method == 'GET':
        config = get_captcha_config()
        verified = get_verified_ips()
        now = time.time()
        active_count = sum(1 for v in verified.values() if v > now)
        return jsonify({
            'config': config,
            'active_ips': active_count,
            'total_verified': len(verified)
        })

    data = request.get_json(silent=True) or {}
    config = get_captcha_config()

    # 基础配置
    config['enabled'] = bool(data.get('enabled', True))
    config['duration_minutes'] = int(data.get('duration_minutes', 30))

    # 图形参数
    for key in ['width', 'height', 'channels', 'loop_frames', 'scroll_speed', 'font_size', 'captcha_length']:
        if key in data:
            try:
                config[key] = int(data[key])
            except:
                pass
    if 'allowed_chars' in data:
        config['allowed_chars'] = data['allowed_chars'].strip()

    save_captcha_config(config)
    return jsonify({'ok': True, 'config': config})

@app.route('/api/admin/captcha/clear', methods=['POST'])
@require_csrf
@require_private_key
def api_admin_captcha_clear():
    if not is_admin():
        return jsonify({'error': '未授权'}), 403
    save_verified_ips({})
    return jsonify({'ok': True})

@app.route('/api/admin/captcha/verified-log', methods=['GET'])
@require_csrf
@require_private_key
def api_admin_captcha_verified_log():
    if not is_admin():
        return jsonify({'error': '未授权'}), 403
    log = get_verified_log()
    # 直接返回原始加密数据，前端自行解密
    return jsonify({'entries': log})

# ═══════════════════════════════════════════════════════════
# 4.6.5  加密工具（用于已验证 IP 加密存储）
# ═══════════════════════════════════════════════════════════
from Crypto.Cipher import AES as _AES_CIPHER
import base64 as _base64

# ── 已验证 IP 日志文件 ──
CAPTCHA_LOG_FILE = os.path.join(CAPTCHA_DIR, 'verified_log.json')

def get_verified_log():
    """获取加密的已验证IP日志"""
    try:
        with open(CAPTCHA_LOG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def save_verified_log(data):
    """保存已验证IP日志"""
    atomic_write(CAPTCHA_LOG_FILE, json.dumps(data, ensure_ascii=False))

# ═══════════════════════════════════════════════════════════
# 修改 mark_captcha_verified：同时写入加密日志
# ═══════════════════════════════════════════════════════════

# === 5. 核心工具函数 ===
def get_client_ip():
    direct_ip = request.remote_addr or '127.0.0.1'
    # 仅当 direct_ip 在可信代理列表中时，才信任 X-Forwarded-For
    if TRUSTED_PROXIES and direct_ip in TRUSTED_PROXIES:
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            # 取第一个 IP（原始客户端）
            return xff.split(',')[0].strip()
    return direct_ip

def get_fp():
    ua = request.headers.get('User-Agent', '')
    return hashlib.sha256(f"{get_client_ip()}|{ua}".encode()).hexdigest()[:16]

def is_admin():
    return session.get('admin') is True

def _migrate_ip_file(filepath, encrypted=False):
    """迁移旧格式（纯IP）到新格式（hash|RSA加密）"""
    if not os.path.exists(filepath):
        return
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    new_lines = []
    changed = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if '|' not in line:   # 旧格式
            ip = line
            ip_hash = sha512(ip)
            enc = rsa_encrypt_report(ip)
            if enc:
                new_lines.append(f"{ip_hash}|{enc}\n")
                changed = True
            else:
                # 加密失败则保留原样（但会丢失）
                pass
        else:
            new_lines.append(line + '\n')
    if changed:
        # 备份原文件
        shutil.copy(filepath, filepath + '.bak')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

def load_whitelist_hashes():
    """返回白名单IP哈希集合（用于速率限制检查）"""
    _migrate_ip_file(WHITE_FILE)
    hashes = set()
    try:
        with open(WHITE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and '|' in line:
                    h = line.split('|')[0]
                    hashes.add(h)
    except Exception:
        pass
    return hashes

def load_whitelist_encrypted():
    """返回白名单加密列表（用于前端展示）"""
    _migrate_ip_file(WHITE_FILE)
    entries = []
    try:
        with open(WHITE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and '|' in line:
                    parts = line.split('|', 1)
                    entries.append({'hash': parts[0], 'encrypted': parts[1]})
    except Exception:
        pass
    return entries

# 同样修改 load_blacklist 和 load_blacklist_encrypted
def load_blacklist_hashes():
    _migrate_ip_file(BLACK_FILE)
    hashes = set()
    try:
        with open(BLACK_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and '|' in line:
                    h = line.split('|')[0]
                    hashes.add(h)
    except Exception:
        pass
    return hashes

def load_blacklist_encrypted():
    _migrate_ip_file(BLACK_FILE)
    entries = []
    try:
        with open(BLACK_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and '|' in line:
                    parts = line.split('|', 1)
                    entries.append({'hash': parts[0], 'encrypted': parts[1]})
    except Exception:
        pass
    return entries

# 修改原有的 load_whitelist / load_blacklist 重命名或保留向后兼容
# 但建议直接修改原函数为返回哈希集合，并保留旧名
def load_whitelist():
    return load_whitelist_hashes()

def load_blacklist():
    return load_blacklist_hashes()

def load_chat():
    with _file_lock:
        with open(CHAT_FILE, 'r', encoding='utf-8') as f:
            chat = json.load(f)
        for m in chat:
            normalize_msg(m)
        return chat

def sha512(s):
    return hashlib.sha512(s.encode()).hexdigest()

def log_ip_visit(ip):
    """记录 IP 访问（按天聚合：SHA512(IP) | RSA(IP) | 当天次数）"""
    date_str = datetime.now(CST).strftime('%Y-%m-%d')
    ip_hash = sha512(ip)
    ip_encrypted = rsa_encrypt_report(ip)

    filepath = os.path.join(IP_DIR, f'ip_{date_str}')

    with _ip_log_lock:
        lines = []
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
        except Exception:
            pass

        new_lines = []
        found = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split('|', 2)
            if len(parts) >= 3 and parts[0].strip() == ip_hash:
                try:
                    count = int(parts[2].strip()) + 1
                except ValueError:
                    count = 1
                new_lines.append(f"{ip_hash} | {ip_encrypted} | {count}\n")
                found = True
            else:
                new_lines.append(stripped + '\n')

        if not found:
            new_lines.append(f"{ip_hash} | {ip_encrypted} | 1\n")

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(''.join(new_lines))

def normalize_msg(m):
    m.setdefault('state', 'enabled')
    m.setdefault('key_hash', '')
    m.setdefault('reports', [])
    return m

def load_rule():
    try:
        return open(RULE_FILE, 'r', encoding='utf-8').read().strip()
    except Exception:
        return ''

def load_threshold():
    try:
        return int(open(THRESHOLD_FILE, 'r', encoding='utf-8').read().strip() or '5')
    except Exception:
        return 5
def load_notices():
    try:
        with open(NOTICE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def save_notices(data):
    atomic_write(NOTICE_FILE, json.dumps(data, ensure_ascii=False))

def rsa_encrypt_report(plaintext):
    """用服务器RSA公钥加密数据（管理员私钥可解密）"""
    try:
        pub = RSA.importKey(open(RSA_PUB, 'rb').read())
        return base64.b64encode(PKCS1_v1_5.new(pub).encrypt(plaintext.encode())).decode()
    except Exception:
        return ''

def encrypt_ip(ip):
    """
    用 RSA 公钥加密 IP 地址。
    返回格式：
      'RSA:<base64>'  — 加密成功，前端可用私钥解密
      'PLAIN:<ip>'    — 加密失败时的降级（保留原始数据不丢失）
    """
    if not ip:
        return ''
    encrypted = rsa_encrypt_report(ip)
    if encrypted:
        return 'RSA:' + encrypted
    return 'PLAIN:' + ip

def check_regex_disable(content):
    rule = load_rule()
    if not rule:
        return False
    try:
        re.compile(rule)
    except re.error:
        return False
    return safe_regex_search(rule, content)

def save_chat(data):
    atomic_write(CHAT_FILE, json.dumps(data, ensure_ascii=False))

def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

# === 新增：后端处理中锁（根治连点重复提交）===
_processing_ips = {}
_processing_lock = threading.Lock()

def acquire_processing_lock(ip, ttl=15):
    now = time.time()
    with _processing_lock:
        if ip in _processing_ips and _processing_ips[ip] > now:
            return False
        _processing_ips[ip] = now + ttl
        return True

def release_processing_lock(ip):
    with _processing_lock:
        _processing_ips.pop(ip, None)

# === 6. 速率限制模块（7秒缓冲锁 + 白名单豁免）===
import sqlite3
import random as _random

_rate_db_path = os.path.join(DATA_DIR, 'rate_limits.db')
_rate_db_lock = threading.Lock()

def _init_rate_db():
    with _rate_db_lock:
        conn = sqlite3.connect(_rate_db_path, timeout=5.0)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS rate_blocks (
                ip TEXT PRIMARY KEY,
                block_until REAL NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

_init_rate_db()

def _is_whitelisted(ip):
    ip_hash = sha512(ip)
    return ip_hash in load_whitelist_hashes()

def check_rate_limit_before(ip):
    _cleanup_rate_limits()
    if _is_whitelisted(ip):
        return True, True, 0, 0
    now = time.time()
    try:
        with _rate_db_lock:
            conn = sqlite3.connect(_rate_db_path, timeout=3.0)
            conn.execute('PRAGMA busy_timeout = 3000')
            cur = conn.execute('SELECT block_until FROM rate_blocks WHERE ip = ?', (ip,))
            row = cur.fetchone()
            conn.close()
            if row and now < row[0]:
                remaining = int(row[0] - now)
                return False, False, row[0], remaining
            return True, False, 0, 0
    except Exception as e:
        print(f"[RATE LIMIT CHECK ERROR] {e}")
        return True, False, 0, 0

def set_rate_limit_after(ip):
    if _is_whitelisted(ip):
        return 0
    block_until = time.time() + 7.0
    try:
        with _rate_db_lock:
            conn = sqlite3.connect(_rate_db_path, timeout=3.0)
            conn.execute('PRAGMA busy_timeout = 3000')
            conn.execute('''
                INSERT INTO rate_blocks (ip, block_until) VALUES (?, ?)
                ON CONFLICT(ip) DO UPDATE SET block_until=excluded.block_until
            ''', (ip, block_until))
            conn.commit()
            conn.close()
        return block_until
    except Exception as e:
        print(f"[RATE LIMIT SET ERROR] {e}")
        return 0

def rate_limit_json(data, status=200, in_whitelist=False, block_until=0):
    resp = make_response(jsonify(data), status)
    resp.headers['X-RateLimit-Whitelisted'] = '1' if in_whitelist else '0'
    if block_until > 0:
        resp.headers['X-RateLimit-BlockUntil'] = str(block_until)
        resp.headers['X-RateLimit-Remaining'] = str(max(0, int(block_until - time.time())))
    return resp

def _cleanup_rate_limits():
    if _random.randint(1, 100) > 5:
        return
    now = time.time()
    try:
        with _rate_db_lock:
            conn = sqlite3.connect(_rate_db_path, timeout=3.0)
            conn.execute('DELETE FROM rate_blocks WHERE block_until < ?', (now,))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[RATE LIMIT CLEANUP ERROR] {e}")

def check_rate_limit(action='read'):
    ip = get_client_ip()
    if _is_whitelisted(ip):
        return None
    if action == 'write':
        allowed, _, block_until, remaining = check_rate_limit_before(ip)
        if not allowed:
            return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, False, block_until)
    return None

# === 7. 安全中间件 ===
@app.before_request
def security_checks():
    if sha512(get_client_ip()) in load_blacklist_hashes():
        return "IP已被封禁，拒绝访问", 403
    if session.get('admin'):
        stored = session.get('fp')
        if stored and stored != get_fp():
            session.clear()

@app.after_request
def secure_headers(response):
    # ★ 记录 IP 访问（排除自身查询接口避免自循环）
    if not request.path.startswith('/api/admin/ip'):
        try:
            log_ip_visit(get_client_ip())
        except Exception:
            pass

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'none'"
    )
    return response

# === 8. 路由：认证与安全 ===
@app.route('/api/csrf')
def api_csrf():
    rl = check_rate_limit('read')
    if rl: return rl
    return jsonify({'token': generate_csrf()})

@app.route('/api/admin/status')
def admin_status():
    rl = check_rate_limit('read')
    if rl: return rl
    return jsonify({
        'logged_in': is_admin(),
        'has_key': session.get('admin_has_key', False)
    })

@app.route('/api/admin/challenge')
def admin_challenge():
    rl = check_rate_limit('read')
    if rl: return rl
    if is_admin():
        return jsonify({'error': '已登录'}), 400
    nonce = secrets.token_urlsafe(32)
    session['challenge_nonce'] = nonce
    session['challenge_time'] = time.time()
    try:
        pub = RSA.importKey(open(RSA_PUB, 'rb').read())
        encrypted = base64.b64encode(PKCS1_v1_5.new(pub).encrypt(nonce.encode())).decode()
        return jsonify({'challenge': encrypted})
    except Exception as e:
        print(f"[ERROR] 公钥加载失败: {e}")
        return jsonify({'challenge': 'ERROR'})

@app.route('/api/admin/verify', methods=['POST'])
@require_csrf
def admin_verify():
    rl = check_rate_limit('write')
    if rl:
        return rl
    data = request.get_json(silent=True) or {}
    plaintext = (data.get('plaintext') or request.form.get('plaintext', '')).strip()
    stored = session.get('challenge_nonce')
    ctime = session.get('challenge_time', 0)
    if not plaintext:
        return "解密结果为空（请检查私钥）", 401
    if not stored:
        return "Session 丢失（请清除 Cookie 后重试）", 401
    if time.time() - ctime > 120:
        return "挑战已过期（请刷新页面重新验证）", 401
    if plaintext != stored:
        return "解密值不匹配（私钥错误或已失效）", 401
    # 登录成功
    session['admin'] = True
    session['admin_has_key'] = True
    session['fp'] = get_fp()
    session.pop('challenge_nonce', None)
    session.pop('challenge_time', None)
    generate_csrf()
    return jsonify({'status': 'ok'})

@app.route('/api/admin/logout', methods=['GET', 'POST'])
@require_csrf
def admin_logout():
    session.clear()
    return jsonify({'status': 'ok'})

# === 9. 路由：基础与留言（v2 三部分格式）===
@app.route('/api/myip')
def my_ip():
    return get_client_ip()

@app.route('/gongyao.txt')
def pub_key():
    try:
        content = open(RSA_PUB, encoding='utf-8').read()
        return content, 200, {'Content-Type': 'text/plain'}
    except FileNotFoundError:
        return "公钥文件未配置", 404
    except Exception:
        return "公钥读取失败", 500

@app.route('/api/footer', methods=['GET'])
def get_footer():
    return open(UNDER_FILE, encoding='utf-8').read()

@app.route('/', methods=['GET', 'POST'])
@require_captcha
def index():
    if request.method == 'POST':
        ip = get_client_ip()
        if not acquire_processing_lock(ip):
            return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)
        try:
            allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
            if not allowed:
                return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)
            data = request.get_json(silent=True) or {}
            if not all(data.get(k) for k in ('rsa_key', 'aes_msg', 'iv')):
                return rate_limit_json({"error": "数据不完整"}, 400, in_wl, block_until)
            rsa_key = data['rsa_key'].replace('\n', '').replace('\r', '').strip()
            iv = data['iv'].replace('\n', '').replace('\r', '').strip()
            aes_msg = data['aes_msg'].replace('\n', '').replace('\r', '').strip()

            server_time = datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')
            server_meta = f"{get_client_ip()} | {server_time}"
            server_enc = rsa_encrypt_report(server_meta)

            content = f"v2|{rsa_key}|{iv}|{server_time}\n{aes_msg}\n{server_enc}"
            with _file_lock:
                seq = get_seq_unlocked()
                atomic_write_unlocked(os.path.join(MSG_DIR, f"留言_{seq}.txt"), content)
            block_until = set_rate_limit_after(ip)
            return rate_limit_json({"status": "ok"}, 200, in_wl, block_until)
        finally:
            release_processing_lock(ip)
    return render_template('index.html')

@app.route('/admin')
def admin_page():
    msgs = []
    files = sorted(
        glob.glob(os.path.join(MSG_DIR, '留言_*.txt')),
        key=lambda x: int(m.group(1)) if (m := re.search(r'(\d+)', os.path.basename(x))) else 0
    )
    for f in files:
        try:
            with open(f, encoding='utf-8') as fh:
                lines = [l.strip() for l in fh.readlines() if l.strip()]
                if len(lines) < 2:
                    continue
                is_v2 = lines[0].startswith('v2|')
                seq = re.search(r'(\d+)', os.path.basename(f)).group(1)
                if is_v2:
                    parts = lines[0].split('|')
                    # v2|rsa_key|iv[|server_time]
                    server_time = parts[3] if len(parts) >= 4 else ''
                    msgs.append({
                        'file': os.path.basename(f),
                        'seq': seq,
                        'rsa_iv': lines[0],
                        'aes_msg': lines[1],
                        'server_enc': lines[2] if len(lines) > 2 else '',
                        'server_time': server_time,
                        'is_v2': True
                    })
                else:
                    if len(lines) < 3:
                        continue
                    msgs.append({
                        'file': os.path.basename(f),
                        'seq': seq,
                        'rsa_iv': lines[0].strip(),
                        'meta_enc': lines[1].strip(),
                        'content_enc': ''.join(lines[2:]).strip(),
                        'is_v2': False
                    })
        except Exception:
            continue
    return render_template('admin.html', messages=msgs)

# === 10. 路由：回复 ===
@app.route('/api/replies', methods=['GET'])
def get_replies():
    rl = check_rate_limit('read')
    if rl: return rl
    reps = []
    # 新格式：回复_{seq}_{num}.txt
    for f in glob.glob(os.path.join(REPLY_DIR, '回复_*_*.txt')):
        m = re.search(r'回复_(\d+)_(\d+)\.txt', os.path.basename(f))
        if not m: continue
        try:
            with open(f, encoding='utf-8') as fh:
                lines = fh.readlines()
                if len(lines) >= 2:
                    reps.append({
                        'seq': m.group(1),
                        'num': int(m.group(2)),
                        'iv': lines[0].strip(),
                        'aes_msg': ''.join(lines[1:]).strip()
                    })
        except Exception:
            continue
    # 旧格式兼容：回复_{seq}.txt → 视为 num=1
    for f in glob.glob(os.path.join(REPLY_DIR, '回复_*.txt')):
        m = re.search(r'回复_(\d+)\.txt', os.path.basename(f))
        if not m: continue
        if any(r['seq'] == m.group(1) and r['num'] == 1 for r in reps):
            continue       # 已有 _1 文件则跳过旧文件
        try:
            with open(f, encoding='utf-8') as fh:
                lines = fh.readlines()
                if len(lines) >= 2:
                    reps.append({
                        'seq': m.group(1),
                        'num': 1,
                        'iv': lines[0].strip(),
                        'aes_msg': ''.join(lines[1:]).strip()
                    })
        except Exception:
            continue
    return jsonify(reps)

@app.route('/api/messages', methods=['GET'])
def get_messages():
    rl = check_rate_limit('read')
    if rl: return rl
    msgs = []
    for f in sorted(
        glob.glob(os.path.join(MSG_DIR, '留言_*.txt')),
        key=lambda x: int(m.group(1)) if (m := re.search(r'(\d+)', os.path.basename(x))) else 0
    ):
        m = re.search(r'(\d+)', os.path.basename(f))
        if not m: continue
        try:
            with open(f, encoding='utf-8') as fh:
                lines = [l.strip() for l in fh.readlines() if l.strip()]
                if len(lines) < 2:
                    continue
                is_v2 = lines[0].startswith('v2|')
                if is_v2:
                    parts = lines[0].split('|')
                    # v2|rsa_key|iv[|server_time]
                    server_time = parts[3] if len(parts) >= 4 else ''
                    msgs.append({
                        'seq': m.group(1),
                        'iv': parts[2] if len(parts) >= 3 else '',
                        'aes_msg': lines[1],
                        'server_enc': lines[2] if len(lines) > 2 else '',
                        'server_time': server_time
                    })
                else:
                    if len(lines) < 3:
                        continue
                    parts = lines[0].split('|')
                    msgs.append({
                        'seq': m.group(1),
                        'iv': parts[1] if len(parts) >= 2 else '',
                        'meta_msg': lines[1],
                        'aes_msg': ''.join(lines[2:]).strip()
                    })
        except Exception:
            continue
    return jsonify(msgs)

@app.route('/api/reply', methods=['POST'])
@require_captcha
@require_csrf
def save_reply():
    if not is_admin(): return "未授权", 403
    data = request.get_json(silent=True) or {}
    if not data.get('seq'): return "缺少序号", 400
    seq = data['seq']
    if not re.match(r'^\d+$', str(seq)): return "无效序号", 400

    # 找出下一个编号
    max_num = 0
    for f in glob.glob(os.path.join(REPLY_DIR, f'回复_{seq}*.txt')):
        m = re.search(r'回复_\d+_(\d+)\.txt', os.path.basename(f))
        if m:
            max_num = max(max_num, int(m.group(1)))
        elif os.path.basename(f) == f'回复_{seq}.txt':
            max_num = max(max_num, 1)

    next_num = max_num + 1
    content = f"{data['iv']}\n{data['aes_msg']}"
    atomic_write(os.path.join(REPLY_DIR, f"回复_{seq}_{next_num}.txt"), content)
    return jsonify({"status": "ok", "num": next_num})

@app.route('/admin/delete/<filename>', methods=['POST'])
@require_csrf
def delete_msg(filename):
    if not is_admin(): return "未授权", 403
    path = safe_resolve(MSG_DIR, filename)
    if not path or not os.path.isfile(path): return "无效文件", 400
    os.remove(path)
    if m := re.search(r'(\d+)', os.path.basename(path)):
        # 删除所有相关回复（新旧格式）
        for f in glob.glob(os.path.join(REPLY_DIR, f'回复_{m.group(1)}*.txt')):
            try:
                os.remove(f)
            except Exception:
                pass
    return "ok"

@app.route('/admin/delete_reply/<seq>', methods=['POST'])
@require_captcha
@require_csrf
def delete_reply(seq):
    if not is_admin(): return "未授权", 403
    if not re.match(r'^\d+$', str(seq)): return "无效序号", 400
    path = safe_resolve(REPLY_DIR, f"回复_{seq}.txt")
    if not path or not os.path.isfile(path): return "无效文件", 400
    os.remove(path)
    return "ok"

@app.route('/admin/delete_reply_file/<filename>', methods=['POST'])
@require_captcha
@require_csrf
def delete_reply_file(filename):
    """删除单条回复（支持多条回复）"""
    if not is_admin(): return "未授权", 403
    path = safe_resolve(REPLY_DIR, filename)
    if not path or not os.path.isfile(path): return "无效文件", 400
    os.remove(path)
    return "ok"

@app.route('/api/footer', methods=['POST'])
@require_captcha
@require_csrf
def update_footer():
    if not is_admin(): return "未授权", 403
    atomic_write(UNDER_FILE, request.form.get('content', ''))
    return "ok"

@app.route('/api/blacklist', methods=['GET', 'POST'])
@require_csrf
def manage_blacklist():
    if not is_admin(): return "未授权", 403
    rl = check_rate_limit('read')
    if rl: return rl
    
    if request.method == 'GET':
        return jsonify(load_blacklist_encrypted())

    data = request.get_json(silent=True) or {}
    action = data.get('action')
    
    _migrate_ip_file(BLACK_FILE)
    lines = []
    try:
        with open(BLACK_FILE, 'r', encoding='utf-8') as f: lines = f.readlines()
    except Exception: lines = []

    new_lines = []
    
    if action == 'add':
        # 添加时：前端传明文 IP，后端计算 hash 并加密
        ip = data.get('ip', '').strip()
        if not ip: return "IP无效", 400
        ip_hash = sha512(ip)
        enc = rsa_encrypt_report(ip)
        if not enc: return "加密失败", 500
        
        found = False
        for line in lines:
            line = line.strip()
            if not line: continue
            h = line.split('|')[0] if '|' in line else ''
            if h == ip_hash:
                found = True
                new_lines.append(f"{ip_hash}|{enc}\n") # 覆盖更新
            else:
                new_lines.append(line + '\n')
        if not found: new_lines.append(f"{ip_hash}|{enc}\n")
        
    elif action == 'remove':
        # ★ 删除时：前端直接传 hash，后端按 hash 匹配删除
        target_hash = data.get('hash', '').strip()
        if not target_hash: return "缺少哈希值", 400
        
        removed = False
        for line in lines:
            line = line.strip()
            if not line: continue
            h = line.split('|')[0] if '|' in line else ''
            if h != target_hash:
                new_lines.append(line + '\n')
            else:
                removed = True
        if not removed:
            return jsonify({'error': 'IP不在黑名单中'}), 404
    else:
        return "无效操作", 400

    atomic_write(BLACK_FILE, ''.join(new_lines))
    return "ok"

@app.route('/api/whitelist', methods=['GET', 'POST'])
@require_csrf
def manage_whitelist():
    if not is_admin(): return "未授权", 403
    rl = check_rate_limit('read')
    if rl: return rl
    
    if request.method == 'GET':
        return jsonify(load_whitelist_encrypted())

    data = request.get_json(silent=True) or {}
    action = data.get('action')
    
    _migrate_ip_file(WHITE_FILE)
    lines = []
    try:
        with open(WHITE_FILE, 'r', encoding='utf-8') as f: lines = f.readlines()
    except Exception: lines = []

    new_lines = []
    
    if action == 'add':
        # 添加时：前端传明文 IP，后端计算 hash 并加密
        ip = data.get('ip', '').strip()
        if not ip: return "IP无效", 400
        ip_hash = sha512(ip)
        enc = rsa_encrypt_report(ip)
        if not enc: return "加密失败", 500
        
        found = False
        for line in lines:
            line = line.strip()
            if not line: continue
            h = line.split('|')[0] if '|' in line else ''
            if h == ip_hash:
                found = True
                new_lines.append(f"{ip_hash}|{enc}\n") # 覆盖更新
            else:
                new_lines.append(line + '\n')
        if not found: new_lines.append(f"{ip_hash}|{enc}\n")
        
    elif action == 'remove':
        # ★ 删除时：前端直接传 hash，后端按 hash 匹配删除
        target_hash = data.get('hash', '').strip()
        if not target_hash: return "缺少哈希值", 400
        
        removed = False
        for line in lines:
            line = line.strip()
            if not line: continue
            h = line.split('|')[0] if '|' in line else ''
            if h != target_hash:
                new_lines.append(line + '\n')
            else:
                removed = True
        if not removed:
            return jsonify({'error': 'IP不在黑名单中'}), 404
    else:
        return "无效操作", 400

    atomic_write(WHITE_FILE, ''.join(new_lines))
    return "ok"

# === 12. 路由：群聊（未改动，与原版一致）===
@app.route('/qun')
def qun_page():
    return render_template('qun.html')

@app.route('/api/qun/status')
def qun_status():
    rl = check_rate_limit('read')
    if rl: return rl
    return read_perm_file()

@app.route('/api/qun', methods=['GET'])
def get_qun():
    rl = check_rate_limit('read')
    if rl: return rl

    chat = load_chat()
    nick = request.args.get('nick', '').strip()
    key_hash = request.args.get('key_hash', '').strip()
    is_admin_user = is_admin()

    # 预先计算"我是谁"（用于 is_owner 判断）
    my_identity = (nick, key_hash) if nick and key_hash else None

    result = []
    for i, m in enumerate(chat):
        normalize_msg(m)
        state = m.get('state', 'enabled')

        # ── 白名单：谁有权看到这条消息？ ──
        allowed = True                           # 默认允许

        if state == 'disabled':
            allowed = False                       # ★ 先全部拒绝
            if is_admin_user:                     # 管理员 → 放行
                allowed = True
            elif my_identity:                     # 消息主人 → 放行
                if m.get('nick') == nick and m.get('key_hash') == key_hash:
                    allowed = True

        if not allowed:
            continue

        result.append({
            'index': i,
            'nick': m['nick'],
            'time': m['time'],
            'content': m['content'],
            'state': state,
            'pinned': bool(m.get('pinned')),
            'is_owner': bool(my_identity and m.get('nick') == nick and m.get('key_hash') == key_hash),
            'report_count': len(m.get('reports', []))
        })

    normal  = [x for x in result if x['state'] in ('enabled', 'disabled') and not x['pinned']]
    forced  = [x for x in result if x['state'] == 'forced' and not x['pinned']]
    pinned  = [x for x in result if x['pinned']]
    ordered = normal + forced + pinned

    return jsonify(ordered)

@app.route('/api/qun', methods=['POST'])
@require_captcha
@require_csrf
def post_qun():
    ip = get_client_ip()
    allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
    if not allowed:
        return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)
    if read_perm_file() == '1':
        return rate_limit_json({"error": "已开启全体禁言"}, 403, in_wl, block_until)
    data = request.get_json(silent=True) or {}
    if not data.get('nick') or not data.get('content'):
        return rate_limit_json({"error": "数据不完整"}, 400, in_wl, block_until)
    if not data.get('key'):
        return rate_limit_json({"error": "请提供密钥"}, 400, in_wl, block_until)
    if data['nick'].strip().lower() == 'admin':
        return rate_limit_json({"error": "禁止使用 admin 作为昵称"}, 400, in_wl, block_until)

    key_hash = sha512(data['key'].strip())
    content = data['content'][:2048]
    initial_state = 'disabled' if check_regex_disable(content) else 'enabled'

    msg = {
        'nick': data['nick'].strip()[:32],
        'time': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
        'ip': encrypt_ip(get_client_ip()),
        'content': content,
        'pinned': False,
        'state': initial_state,
        'key_hash': key_hash,
        'reports': []
    }
    def updater(chat):
        chat.append(msg)
    atomic_chat_update(updater)

    block_until = set_rate_limit_after(ip)
    return rate_limit_json({"status": "ok", "state": initial_state}, 200, in_wl, block_until)

@app.route('/api/qun/revoke/<int:index>', methods=['POST'])

@require_csrf
def revoke_qun_msg(index):
    ip = get_client_ip()
    allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
    if not allowed:
        return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)
    data = request.get_json(silent=True) or {}
    nick = data.get('nick', '').strip()
    key = data.get('key', '').strip()
    if not nick or not key:
        return rate_limit_json({"error": "请提供昵称和密钥"}, 400, in_wl, block_until)
    key_hash = sha512(key)

    with _file_lock:
        with open(CHAT_FILE, 'r', encoding='utf-8') as f:
            chat = json.load(f)
        if not (0 <= index < len(chat)):
            return rate_limit_json({"error": "消息不存在"}, 404, in_wl, block_until)
        m = chat[index]
        if m.get('nick') != nick or m.get('key_hash') != key_hash:
            return rate_limit_json({"error": "身份校验失败，无权撤回此消息"}, 403, in_wl, block_until)
        m['state'] = 'disabled'
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(CHAT_FILE), suffix='.tmp')
        try:
            os.write(fd, json.dumps(chat, ensure_ascii=False).encode('utf-8'))
            os.close(fd)
            os.replace(tmp_path, CHAT_FILE)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    block_until = set_rate_limit_after(ip)
    return rate_limit_json({"ok": True}, 200, in_wl, block_until)

@app.route('/api/qun/report/<int:index>', methods=['POST'])
@require_captcha
@require_csrf
def report_qun_msg(index):
    ip = get_client_ip()
    allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
    if not allowed:
        return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)
    data = request.get_json(silent=True) or {}
    nick = data.get('nick', '').strip()
    key = data.get('key', '').strip()

    with _file_lock:
        with open(CHAT_FILE, 'r', encoding='utf-8') as f:
            chat = json.load(f)
        if not (0 <= index < len(chat)):
            return rate_limit_json({"error": "消息不存在"}, 404, in_wl, block_until)
        m = chat[index]
        if m.get('state') == 'forced':
            return rate_limit_json({"error": "公告不可举报"}, 403, in_wl, block_until)

        reporter_ip = get_client_ip()
        ip_hash = sha512(reporter_ip)
        m.setdefault('reports', [])
        if any(r.get('ip_hash') == ip_hash for r in m['reports']):
            return rate_limit_json({'error': '您已经举报过这条消息，请勿重复举报'}, 429, in_wl, block_until)

        plaintext = f"{reporter_ip}|{nick}|{key}"
        encrypted = rsa_encrypt_report(plaintext)

        report = {
            'ip_hash': ip_hash,
            'encrypted': encrypted,
            'time': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
            'msg_index': index
        }
        m['reports'].append(report)
        threshold = load_threshold()
        total_reports = len(m['reports'])
        if total_reports >= threshold:
            m['state'] = 'disabled'

        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(CHAT_FILE), suffix='.tmp')
        try:
            os.write(fd, json.dumps(chat, ensure_ascii=False).encode('utf-8'))
            os.close(fd)
            os.replace(tmp_path, CHAT_FILE)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    block_until = set_rate_limit_after(ip)
    return rate_limit_json({
        'ok': True,
        'auto_disabled': m['state'] == 'disabled' and total_reports >= threshold
    }, 200, in_wl, block_until)

@app.route('/admin/qun')
def admin_qun_page():
    return render_template('admin_qun.html')

@app.route('/api/admin/qun', methods=['GET'])
@require_csrf
def get_admin_qun():
    if not is_admin(): return "未授权", 403
    chat = load_chat()
    result = []
    for i, m in enumerate(chat):
        normalize_msg(m)
        raw_ip = m.get('ip', '')
        # 兼容旧数据：如果 IP 不是 'RSA:' 或 'PLAIN:' 开头，则为历史明文，标记为 PLAIN
        if raw_ip and not raw_ip.startswith(('RSA:', 'PLAIN:')):
            raw_ip = 'PLAIN:' + raw_ip
        result.append({
            'index': i,
            'nick': m['nick'],
            'time': m['time'],
            'content': m['content'],
            'ip': raw_ip,
            'state': m.get('state', 'enabled'),
            'pinned': bool(m.get('pinned')),
            'key_hash': m.get('key_hash', ''),
            'reports': m.get('reports', []),
            'report_count': len(m.get('reports', []))
        })
    return jsonify(result)

@app.route('/api/admin/qun/delete/<int:index>', methods=['POST'])
@require_csrf
def delete_qun_msg(index):
    if not is_admin(): return "未授权", 403
    def updater(chat):
        if 0 <= index < len(chat):
            chat.pop(index)
    atomic_chat_update(updater)
    return "ok"

@app.route('/api/admin/qun/state/<int:index>', methods=['POST'])
@require_csrf
def toggle_qun_state(index):
    if not is_admin(): return "未授权", 403
    data = request.get_json(silent=True) or {}
    new_state = data.get('state', '').strip()
    if new_state not in ('enabled', 'disabled', 'forced'):
        return "无效状态（应为 enabled / disabled / forced）", 400
    def updater(chat):
        if 0 <= index < len(chat):
            normalize_msg(chat[index])
            chat[index]['state'] = new_state
    atomic_chat_update(updater)
    return jsonify({'ok': True, 'state': new_state})

@app.route('/api/admin/qun/announce', methods=['POST'])
@require_csrf
def send_announce():
    if not is_admin(): return "未授权", 403
    data = request.get_json(silent=True) or {}
    content = data.get('content', '').strip()
    if not content: return "内容不能为空", 400
    msg = {
        'nick': 'admin',
        'time': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
        'ip': encrypt_ip(get_client_ip()),
        'content': content,
        'pinned': False,
        'state': 'forced',
        'key_hash': '',
        'reports': []
    }
    def updater(chat):
        chat.append(msg)
    atomic_chat_update(updater)
    return {"status": "ok"}, 200

@app.route('/api/admin/qun/permission', methods=['GET', 'POST'])
@require_csrf
def manage_perm():
    if not is_admin(): return "未授权", 403
    if request.method == 'POST':
        atomic_write(PERM_FILE, '1' if request.form.get('val') == '1' else '0')
        return "ok"
    return read_perm_file()

@app.route('/api/admin/qun/pin/<int:index>', methods=['POST'])
@require_csrf
def toggle_pin(index):
    if not is_admin(): return "未授权", 403
    def updater(chat):
        if 0 <= index < len(chat):
            chat[index]['pinned'] = not chat[index].get('pinned', False)
    atomic_chat_update(updater)
    return "ok"

@app.route('/api/admin/qun/rule', methods=['GET', 'POST'])
@require_csrf
def manage_rule():
    if not is_admin(): return "未授权", 403
    if request.method == 'GET':
        return jsonify({'rule': load_rule()})
    data = request.get_json(silent=True) or {}
    rule = data.get('rule', '').strip()
    force = data.get('force', False)
    if rule and _is_redos_dangerous(rule):
        if not force:
            return jsonify({
                'error': '正则模式包含危险的嵌套量词，可能导致服务卡死。请修改正则或确认风险后强制保存。',
                'dangerous': True
            }), 400
    try:
        re.compile(rule)
    except re.error as e:
        return jsonify({'error': f'正则语法错误: {e}'}), 400
    atomic_write(RULE_FILE, rule)
    return jsonify({'ok': True, 'rule': rule})

@app.route('/api/admin/qun/rule/apply', methods=['POST'])
@require_csrf
def apply_rule():
    if not is_admin(): return "未授权", 403
    rule = load_rule()
    if not rule:
        return "正则规则为空", 400
    try:
        re.compile(rule)
    except re.error as e:
        return f"正则语法错误: {e}", 400
    count = 0
    def updater(chat):
        nonlocal count
        for m in chat:
            normalize_msg(m)
            if m.get('state') == 'enabled':
                try:
                    if safe_regex_search(rule, m.get('content', '')):
                        m['state'] = 'disabled'
                        count += 1
                except Exception:
                    pass
    atomic_chat_update(updater)
    return jsonify({'ok': True, 'disabled_count': count})

@app.route('/api/admin/qun/threshold', methods=['GET', 'POST'])
@require_csrf
def manage_threshold():
    if not is_admin(): return "未授权", 403
    if request.method == 'GET':
        return jsonify({'threshold': load_threshold()})
    data = request.get_json(silent=True) or {}
    val = data.get('threshold', '5').strip()
    try:
        val_int = int(val)
        if val_int < 1:
            return "阈值必须 ≥ 1", 400
    except ValueError:
        return "阈值必须是整数", 400
    atomic_write(THRESHOLD_FILE, str(val_int))
    return jsonify({'ok': True, 'threshold': val_int})
# ═══════════════════════════════════════════════════════════
# 15. 路由：IP 访问记录管理
# ═══════════════════════════════════════════════════════════
@app.route('/admin/ip')
def admin_ip_page():
    return render_template('admin_ip.html')

@app.route('/api/admin/ip/data', methods=['GET'])
@require_csrf
@require_private_key
def get_ip_data():
    """查询一段日期范围内的 IP 访问统计（含白名单标注）"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    start_str = request.args.get('start', '').strip()
    end_str   = request.args.get('end',   '').strip()

    if not re.match(r'^\d{4}-\d{2}-\d{2}$', start_str) or \
       not re.match(r'^\d{4}-\d{2}-\d{2}$', end_str):
        return jsonify({'error': '日期格式错误（YYYY-MM-DD）'}), 400

    whitelist = load_whitelist()
    wl_hashes = {sha512(ip) for ip in whitelist}

    aggregated = {}
    try:
        for fname in os.listdir(IP_DIR):
            m = re.match(r'^ip_(\d{4}-\d{2}-\d{2})$', fname)
            if not m:
                continue
            date_str = m.group(1)
            if date_str < start_str or date_str > end_str:
                continue

            filepath = os.path.join(IP_DIR, fname)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split('|', 2)
                        if len(parts) < 3:
                            continue
                        h = parts[0].strip()
                        enc = parts[1].strip()
                        try:
                            cnt = int(parts[2].strip())
                        except ValueError:
                            cnt = 0
                        if h not in aggregated:
                            aggregated[h] = {'encrypted': enc, 'count': 0}
                        aggregated[h]['count'] += cnt
                        aggregated[h]['encrypted'] = enc
            except Exception:
                continue
    except Exception:
        pass

    records = []
    total_visits = 0
    total_visits_non_wl = 0
    unique_ips_non_wl = 0

    for h, v in aggregated.items():
        is_wl = h in wl_hashes
        records.append({
            'hash': h,
            'encrypted': v['encrypted'],
            'count': v['count'],
            'whitelisted': is_wl
        })
        total_visits += v['count']
        if not is_wl:
            total_visits_non_wl += v['count']
            unique_ips_non_wl += 1

    records.sort(key=lambda x: x['count'], reverse=True)

    return jsonify({
        'records': records,
        'total_visits': total_visits,
        'unique_ips': len(records),
        'total_visits_non_wl': total_visits_non_wl,
        'unique_ips_non_wl': unique_ips_non_wl
    })

# ═══════════════════════════════════════════════════════════
# 13. 路由：投票系统（v2 — 服务器独立加密 IP|时间）
# ═══════════════════════════════════════════════════════════
@app.route('/vote')
def vote_page():
    return render_template('vote.html')

@app.route('/api/votes', methods=['GET'])
def list_votes():
    rl = check_rate_limit('read')
    if rl:
        return rl
    os.makedirs(VOTE_DIR, exist_ok=True)
    polls = []
    try:
        entries = sorted(os.listdir(VOTE_DIR))
    except Exception:
        entries = []
    for d in entries:
        poll_dir = os.path.join(VOTE_DIR, d)
        if not os.path.isdir(poll_dir):
            continue
        cfg_path = os.path.join(poll_dir, 'config.json')
        if not os.path.exists(cfg_path):
            continue
        try:
            cfg = json.load(open(cfg_path, 'r', encoding='utf-8'))
            vote_files = glob.glob(os.path.join(poll_dir, '投票_*.txt'))
            polls.append({
                'id': d,
                'title': cfg.get('title', d),
                'options': cfg.get('options', []),
                'custom': cfg.get('custom', False),
                'customHint': cfg.get('customHint', ''),
                'allowEdit': cfg.get('allowEdit', False),
                'minSelect': cfg.get('minSelect', 1),
                'maxSelect': cfg.get('maxSelect', 1),
                'total_votes': len(vote_files),
                'created_at': cfg.get('created_at', '')
            })
        except Exception:
            continue
    return jsonify(polls)

@app.route('/api/votes/<poll_id>', methods=['POST'])
@require_captcha
@require_csrf
def submit_vote(poll_id):
    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)
    try:
        allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
        if not allowed:
            return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)

        poll_dir = safe_vote_dir(poll_id)
        if not poll_dir or not os.path.isdir(poll_dir):
            return rate_limit_json({"error": "投票不存在"}, 404, in_wl, block_until)

        data = request.get_json(silent=True) or {}
        if not all(data.get(k) for k in ('rsa_key', 'aes_msg', 'iv', 'key_hash')):
            return rate_limit_json({"error": "数据不完整（缺少 rsa_key / aes_msg / iv / key_hash）"}, 400, in_wl, block_until)

        rsa_key = data['rsa_key'].replace('\n', '').replace('\r', '').strip()
        iv = data['iv'].replace('\n', '').replace('\r', '').strip()
        aes_msg = data['aes_msg'].replace('\n', '').replace('\r', '').strip()
        key_hash = data['key_hash'].strip()
        edit_token = secrets.token_urlsafe(24)

        # ★ 读取备注
        remark_iv = data.get('remark_iv', '').strip()
        remark_aes_msg = data.get('remark_aes_msg', '').strip()
        remark_line = f"{remark_iv}|{remark_aes_msg}"

        server_time = datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')
        server_meta = f"{get_client_ip()} | {server_time}"
        server_enc = rsa_encrypt_report(server_meta)

        # 写入文件：v2|rsa_key|iv\n aes_msg\n server_enc\n edit_token\n key_hash\n remark_line
        content = f"v2|{rsa_key}|{iv}\n{aes_msg}\n{server_enc}\n{edit_token}\n{key_hash}\n{remark_line}"

        with _file_lock:
            seq = get_vote_seq_unlocked(poll_dir)
            atomic_write_unlocked(os.path.join(poll_dir, f"投票_{seq}.txt"), content)

        block_until = set_rate_limit_after(ip)
        return rate_limit_json({'status': 'ok', 'seq': seq, 'edit_token': edit_token}, 200, in_wl, block_until)
    finally:
        release_processing_lock(ip)

@app.route('/api/votes/<poll_id>/<int:seq>', methods=['PUT'])
@require_csrf
def modify_vote(poll_id, seq):
    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)
    try:
        allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
        if not allowed:
            return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)

        poll_dir = safe_vote_dir(poll_id)
        if not poll_dir or not os.path.isdir(poll_dir):
            return rate_limit_json({"error": "投票不存在"}, 404, in_wl, block_until)

        filepath = safe_resolve(poll_dir, f"投票_{seq}.txt")
        if not filepath or not os.path.isfile(filepath):
            return rate_limit_json({"error": "投票记录不存在"}, 404, in_wl, block_until)

        # 读取原文件
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [l.rstrip('\n') for l in f.readlines()]
        # 确保至少6行
        while len(lines) < 6:
            lines.append('')

        # 检查原文件格式
        if len(lines) < 5 or not lines[0].startswith('v2|'):
            return rate_limit_json({"error": "原投票文件格式无效"}, 400, in_wl, block_until)

        stored_key_hash = lines[4].strip()
        data = request.get_json(silent=True) or {}
        provided_key_hash = data.get('original_key_hash', '').strip()
        if not stored_key_hash or stored_key_hash != provided_key_hash:
            return rate_limit_json({"error": "原 AES 密钥哈希验证失败，无权修改此投票"}, 403, in_wl, block_until)

        if not all(data.get(k) for k in ('rsa_key', 'aes_msg', 'iv')):
            return rate_limit_json({"error": "数据不完整（缺少 rsa_key / aes_msg / iv）"}, 400, in_wl, block_until)

        # 更新内容行
        lines[1] = data['aes_msg'].replace('\n', '').replace('\r', '').strip()
        # 更新第一行的 rsa_key 和 iv
        rsa_key = data['rsa_key'].replace('\n', '').replace('\r', '').strip()
        iv = data['iv'].replace('\n', '').replace('\r', '').strip()
        # 保留原 server_enc 和 edit_token，但可以重新生成或保留
        # 我们保留原 server_enc（第3行）和 edit_token（第4行）以及 key_hash（第5行）
        # 但需要更新第一行的 rsa_key 和 iv
        parts = lines[0].split('|')
        if len(parts) >= 3:
            parts[1] = rsa_key
            parts[2] = iv
            lines[0] = '|'.join(parts)

        # ★ 更新备注（如果有提供）
        new_remark_iv = data.get('remark_iv', '').strip()
        new_remark_aes = data.get('remark_aes_msg', '').strip()
        if 'remark_iv' in data or 'remark_aes_msg' in data:
            lines[5] = f"{new_remark_iv}|{new_remark_aes}"

        # 写回文件
        content = "\n".join(lines)
        atomic_write(filepath, content)

        block_until = set_rate_limit_after(ip)
        return rate_limit_json({'status': 'ok', 'seq': seq}, 200, in_wl, block_until)
    finally:
        release_processing_lock(ip)

@app.route('/admin/vote')
def admin_vote_page():
    return render_template('admin_vote.html')

@app.route('/api/admin/votes/create', methods=['POST'])
@require_csrf
@require_private_key
def create_vote():
    if not is_admin():
        return "未授权", 403

    data = request.get_json(silent=True) or {}
    title = data.get('title', '').strip()
    options = data.get('options', [])
    custom = data.get('custom', False)
    custom_hint = data.get('customHint', '')
    allow_edit = data.get('allowEdit', False)
    min_select = data.get('minSelect', 1)
    max_select = data.get('maxSelect', 1)
    if not title:
        return jsonify({'error': '标题不能为空'}), 400
    if len(options) < 2:
        return jsonify({'error': '至少需要2个选项'}), 400
    try:
        min_select = int(min_select)
        max_select = int(max_select)
    except (ValueError, TypeError):
        return jsonify({'error': 'minSelect 和 maxSelect 必须是整数'}), 400
    total = len(options)
    if min_select < 1:
        return jsonify({'error': '最少可选数不能小于 1'}), 400
    if min_select >= total:
        return jsonify({'error': f'最少可选数必须小于选项总数({total})'}), 400
    if max_select < min_select:
        return jsonify({'error': f'最多可选数({max_select})不能小于最少可选数({min_select})'}), 400
    if max_select > total:
        return jsonify({'error': f'最多可选数({max_select})不能超过选项总数({total})'}), 400
    poll_id = secrets.token_hex(4)
    poll_dir = os.path.join(VOTE_DIR, poll_id)
    os.makedirs(poll_dir, exist_ok=True)
    cfg = {
        'title': title,
        'options': options,
        'custom': custom,
        'customHint': custom_hint,
        'allowEdit': allow_edit,
        'minSelect': min_select,
        'maxSelect': max_select,
        'created_at': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')
    }
    atomic_write(os.path.join(poll_dir, 'config.json'),
                 json.dumps(cfg, ensure_ascii=False))
    return jsonify({'ok': True, 'id': poll_id})

@app.route('/api/admin/votes/<poll_id>/data', methods=['GET'])
@require_csrf
@require_private_key
def get_poll_data(poll_id):
    if not is_admin():
        return "未授权", 403

    poll_dir = safe_vote_dir(poll_id)
    if not poll_dir or not os.path.isdir(poll_dir):
        return "投票不存在", 404

    cfg_path = os.path.join(poll_dir, 'config.json')
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)

    votes = []
    for f in sorted(glob.glob(os.path.join(poll_dir, '投票_*.txt')),
                    key=lambda x: int(m.group(1)) if (m := re.search(r'(\d+)', os.path.basename(x))) else 0):
        m = re.search(r'(\d+)', os.path.basename(f))
        if not m:
            continue
        try:
            with open(f, encoding='utf-8') as fh:
                lines = [l.strip() for l in fh.readlines() if l.strip()]
                if len(lines) < 3:
                    continue
                is_v2 = lines[0].startswith('v2|')
                # 解析备注行（第6行，索引5）
                remark_line = lines[5].strip() if len(lines) >= 6 else ''
                remark_parts = remark_line.split('|', 1)
                remark_iv = remark_parts[0] if len(remark_parts) >= 1 else ''
                remark_aes_msg = remark_parts[1] if len(remark_parts) >= 2 else ''

                if is_v2:
                    parts = lines[0].split('|')
                    votes.append({
                        'seq': m.group(1),
                        'rsa_key': parts[1] if len(parts) >= 2 else '',
                        'iv': parts[2] if len(parts) >= 3 else '',
                        'aes_msg': lines[1],
                        'server_enc': lines[2] if len(lines) > 2 else '',
                        'edit_token': lines[3].strip() if len(lines) >= 4 else '',
                        'remark_iv': remark_iv,
                        'remark_aes_msg': remark_aes_msg
                    })
                else:
                    parts = lines[0].split('|')
                    votes.append({
                        'seq': m.group(1),
                        'rsa_key': parts[0] if len(parts) >= 1 else '',
                        'iv': parts[1] if len(parts) >= 2 else '',
                        'meta_enc': lines[1].strip(),
                        'content_enc': lines[2].strip(),
                        'edit_token': lines[3].strip() if len(lines) >= 4 else '',
                        'remark_iv': remark_iv,
                        'remark_aes_msg': remark_aes_msg
                    })
        except Exception:
            continue

    return jsonify({
        'config': cfg,
        'votes': votes
    })

@app.route('/api/admin/votes/<poll_id>', methods=['DELETE'])
@require_csrf
@require_private_key
def delete_poll(poll_id):
    if not is_admin():
        return "未授权", 403
    poll_dir = safe_vote_dir(poll_id)
    if not poll_dir or not os.path.isdir(poll_dir):
        return "投票不存在", 404
    shutil.rmtree(poll_dir)
    return "ok"

@app.route('/api/admin/votes/<poll_id>/<int:seq>', methods=['DELETE'])
@require_csrf
@require_private_key
def delete_vote(poll_id, seq):
    if not is_admin():
        return "未授权", 403
    poll_dir = safe_vote_dir(poll_id)
    if not poll_dir or not os.path.isdir(poll_dir):
        return "投票不存在", 404
    filepath = safe_resolve(poll_dir, f"投票_{seq}.txt")
    if not filepath or not os.path.isfile(filepath):
        return "无效文件", 400
    os.remove(filepath)
    return "ok"

# ═══════════════════════════════════════════════════════════
# 14. 后台自动正则匹配（每2秒检查，匹配即禁用）
# ═══════════════════════════════════════════════════════════
# === 14. 后台自动正则匹配（增量扫描：仅检查上次之后新增的消息）===
_last_regex_scan_index = 0
_regex_scan_lock = threading.Lock()

def auto_regex_check_loop():
    global _last_regex_scan_index
    while True:
        time.sleep(2)
        rule = load_rule()

        with _regex_scan_lock:
            chat = load_chat()
            total = len(chat)

            # 规则为空时：直接跳到最新，避免规则下次上线后回溯扫描全量旧消息
            if not rule:
                _last_regex_scan_index = total
                continue

            try:
                re.compile(rule)
            except re.error:
                _last_regex_scan_index = total   # 规则非法也跳过，避免反复报错
                continue

            start = _last_regex_scan_index
            if start >= total:
                continue

            changed = False
            for i in range(start, total):
                m = chat[i]
                normalize_msg(m)
                if m.get('state') == 'enabled':
                    try:
                        if safe_regex_search(rule, m.get('content', '')):
                            m['state'] = 'disabled'
                            changed = True
                    except Exception:
                        pass

            if changed:
                save_chat(chat)

            _last_regex_scan_index = total

auto_regex_thread = threading.Thread(target=auto_regex_check_loop, daemon=True)
auto_regex_thread.start()
# ═══════════════════════════════════════════════════════════
# 14.5 聊天消息定时清理（每1小时检查，删除超过 x 小时的消息）
# ═══════════════════════════════════════════════════════════
def load_chat_retention():
    try:
        return int(open(CHAT_RETENTION_FILE, 'r', encoding='utf-8').read().strip() or '0')
    except Exception:
        return 0

def chat_cleanup_loop():
    while True:
        time.sleep(3600)  # 每小时一次
        try:
            hours = load_chat_retention()
            if hours <= 0:
                continue
            cutoff = datetime.now(CST) - timedelta(hours=hours)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            deleted = 0
            with _file_lock:
                for fname in list(os.listdir(CHAT_DIR)):
                    if not fname.endswith('.txt'):
                        continue
                    filepath = os.path.join(CHAT_DIR, fname)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                        if len(lines) < 4:
                            continue
                        # 服务器时间在第4行（索引3），格式：加密IP | 时间
                        last_line = lines[3].strip()
                        admin_parts = last_line.split('|', 1)
                        server_time = admin_parts[1].strip() if len(admin_parts) >= 2 else ''
                        if server_time and server_time < cutoff_str:
                            os.remove(filepath)
                            deleted += 1
                    except Exception:
                        continue
            if deleted:
                print(f"[CHAT CLEANUP] 已删除 {deleted} 条超过 {hours} 小时的聊天消息")
        except Exception as e:
            print(f"[CHAT CLEANUP ERROR] {e}")

chat_cleanup_thread = threading.Thread(target=chat_cleanup_loop, daemon=True)
chat_cleanup_thread.start()
# ═══════════════════════════════════════════════════════════
# 16. 路由：公告板（群聊减配版 — 仅管理员可发/删，链接写在内容里）
# ═══════════════════════════════════════════════════════════
@app.route('/notice')
def notice_page():
    return render_template('notice.html')

@app.route('/admin/notice')
def admin_notice_page():
    return render_template('admin_notice.html')

@app.route('/api/notice', methods=['GET'])
def get_notices():
    """公开接口：获取所有公告（置顶优先，再按时间倒序）"""
    # ★ 公开接口也要限流
    rl = check_rate_limit('read')
    if rl:
        return rl

    notices = load_notices()
    pinned = [n for n in notices if n.get('pinned')]
    unpinned = [n for n in notices if not n.get('pinned')]
    pinned.sort(key=lambda x: x.get('time', ''), reverse=True)
    unpinned.sort(key=lambda x: x.get('time', ''), reverse=True)
    return jsonify(pinned + unpinned)

@app.route('/api/admin/notice', methods=['POST'])
@require_csrf
@require_private_key
def create_notice():
    """管理员发公告"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    # ★ 写操作限流
    rl = check_rate_limit('write')
    if rl:
        return rl

    ip = get_client_ip()
    # ★ 防连点重复提交
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)

    try:
        data = request.get_json(silent=True) or {}
        content = (data.get('content') or '').strip()
        if not content:
            return jsonify({'error': '内容不能为空'}), 400
        if len(content) > 4096:
            return jsonify({'error': '内容过长（最多4096字符）'}), 400

        notice = {
            'content': content,
            'time': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
            'pinned': False
        }

        notices = load_notices()
        # ★ 公告数量上限（防止泛滥）
        if len(notices) >= 200:
            return jsonify({'error': '公告数量已达上限（200条），请先清理旧公告'}), 400

        notices.append(notice)
        save_notices(notices)

        return jsonify({'ok': True, 'index': len(notices) - 1})
    finally:
        release_processing_lock(ip)

@app.route('/api/admin/notice/delete/<int:index>', methods=['POST'])
@require_csrf
@require_private_key
def delete_notice(index):
    """管理员删除公告"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    # ★ 写操作限流
    rl = check_rate_limit('write')
    if rl:
        return rl

    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)

    try:
        notices = load_notices()
        if not (0 <= index < len(notices)):
            return jsonify({'error': '公告不存在'}), 404

        notices.pop(index)
        save_notices(notices)
        return jsonify({'ok': True})
    finally:
        release_processing_lock(ip)

@app.route('/api/admin/notice/pin/<int:index>', methods=['POST'])
@require_csrf
@require_private_key
def toggle_notice_pin(index):
    """管理员置顶/取消置顶"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    # ★ 写操作限流
    rl = check_rate_limit('write')
    if rl:
        return rl

    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)

    try:
        notices = load_notices()
        if not (0 <= index < len(notices)):
            return jsonify({'error': '公告不存在'}), 404

        notices[index]['pinned'] = not notices[index].get('pinned', False)
        save_notices(notices)
        return jsonify({'ok': True, 'pinned': notices[index]['pinned']})
    finally:
        release_processing_lock(ip)
# ═══════════════════════════════════════════════════════════
# 17. 路由：端到端加密聊天
# ═══════════════════════════════════════════════════════════
def safe_chat_hash(h):
    """校验公钥哈希格式：16位小写hex"""
    if isinstance(h, str) and re.match(r'^[a-f0-9]{16}$', h):
        return h
    return None
def get_report_seq():
    """获取下一个举报编号"""
    with _file_lock:
        files = glob.glob(os.path.join(REPORT_DIR, 'report_*.json'))
        seqs = [int(m.group(1)) for f in files if (m := re.search(r'report_(\d+)\.json', os.path.basename(f)))]
        return max(seqs) + 1 if seqs else 1

def is_message_reported(filename):
    """检查消息是否已被举报（未处理）"""
    try:
        for fname in os.listdir(REPORT_DIR):
            if not fname.endswith('.json'):
                continue
            try:
                with open(os.path.join(REPORT_DIR, fname), 'r', encoding='utf-8') as f:
                    report = json.load(f)
                if report.get('filename') == filename and report.get('status') != 'resolved':
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False

def get_chat_seq_unlocked(receiver_hash):
    pattern = os.path.join(CHAT_DIR, f'{receiver_hash}_*.txt')
    files = glob.glob(pattern)
    seqs = []
    for f in files:
        m = re.search(r'_(\d+)\.txt$', os.path.basename(f))
        if m:
            seqs.append(int(m.group(1)))
    return max(seqs) + 1 if seqs else 1

def get_chat_seq(receiver_hash):
    with _file_lock:
        return get_chat_seq_unlocked(receiver_hash)

@app.route('/chat')
def chat_page():
    return render_template('chat.html')

@app.route('/admin/chat')
def admin_chat_page():
    return render_template('admin_chat.html')

@app.route('/api/chat/send', methods=['POST'])
@require_captcha
@require_csrf
def chat_send():
    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)
    try:
        allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
        if not allowed:
            return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)

        data = request.get_json(silent=True) or {}
        if not all(data.get(k) for k in ('sender_pub', 'receiver_hash', 'iv', 'wrapped_key', 'aes_content')):
            return rate_limit_json({"error": "数据不完整"}, 400, in_wl, block_until)

        sender_pub = data['sender_pub'].replace('\n', '').replace('\r', '').strip()
        receiver_hash = data['receiver_hash'].strip().lower()
        iv = data['iv'].replace('\n', '').replace('\r', '').strip()
        wrapped_key = data['wrapped_key'].replace('\n', '').replace('\r', '').strip()
        aes_content = data['aes_content'].replace('\n', '').replace('\r', '').strip()

        # 新增：消息过期时间
        expire_at = data.get('expire_at', '').strip()
        if expire_at:
            if not re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', expire_at):
                return rate_limit_json({"error": "过期时间格式无效"}, 400, in_wl, block_until)
            try:
                expire_dt = datetime.strptime(expire_at, '%Y-%m-%d %H:%M:%S').replace(tzinfo=CST)
                if expire_dt <= datetime.now(CST):
                    return rate_limit_json({"error": "过期时间必须是未来时间"}, 400, in_wl, block_until)
            except ValueError:
                return rate_limit_json({"error": "过期时间格式无效"}, 400, in_wl, block_until)
        # 校验哈希格式
        if not safe_chat_hash(receiver_hash):
            return rate_limit_json({"error": "接收方哈希格式无效"}, 400, in_wl, block_until)

        # 校验 sender_pub 基本格式（PEM RSA公钥）
        if not (sender_pub.startswith('-----BEGIN') and 'PUBLIC KEY' in sender_pub):
            return rate_limit_json({"error": "发送方公钥格式无效"}, 400, in_wl, block_until)

        # 限制长度
        if len(sender_pub) > 2048:
            return rate_limit_json({"error": "公钥过长"}, 400, in_wl, block_until)
        if len(wrapped_key) > 2048:
            return rate_limit_json({"error": "包裹密钥过长"}, 400, in_wl, block_until)
        if len(aes_content) > 32768:
            return rate_limit_json({"error": "密文过长"}, 400, in_wl, block_until)

        # 服务器添加 IP 和时间
        server_time = datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')
        admin_ip_enc = rsa_encrypt_report(ip)

        content = (
            f"v2|{sender_pub}|{iv}|{expire_at}\n"
            f"{wrapped_key}\n"
            f"{aes_content}\n"
            f"{admin_ip_enc} | {server_time}"
        )

        with _file_lock:
            seq = get_chat_seq_unlocked(receiver_hash)
            filename = f"{receiver_hash}_{seq:04d}.txt"
            atomic_write_unlocked(os.path.join(CHAT_DIR, filename), content)

        block_until = set_rate_limit_after(ip)
        return rate_limit_json({"status": "ok", "seq": seq, "filename": filename}, 200, in_wl, block_until)
    finally:
        release_processing_lock(ip)


@app.route('/api/chat/poll', methods=['POST'])
@require_captcha
def chat_poll():
    """轮询新消息：前端上传公钥哈希列表 + sender_hashes + since时间戳"""
    rl = check_rate_limit('read')
    if rl:
        return rl

    data = request.get_json(silent=True) or {}
    hashes = data.get('hashes', [])
    sender_hashes = data.get('sender_hashes', [])
    since = data.get('since', '').strip()

    # 校验接收方哈希
    valid_hashes = set()
    for h in hashes:
        h = str(h).strip().lower()
        if safe_chat_hash(h):
            valid_hashes.add(h)
        if len(valid_hashes) >= 4:
            break

    # ★ 校验发送方哈希
    valid_sender_hashes = set()
    for h in sender_hashes:
        h = str(h).strip().lower()
        if safe_chat_hash(h):
            valid_sender_hashes.add(h)
        if len(valid_sender_hashes) >= 4:
            break

    if not valid_hashes and not valid_sender_hashes:
        return jsonify({"messages": [], "server_time": datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')})

    messages = []
    try:
        for fname in sorted(os.listdir(CHAT_DIR)):
            if not fname.endswith('.txt'):
                continue
            m = re.match(r'^([a-f0-9]{16})_(\d+)\.txt$', fname)
            if not m:
                continue
            fhash = m.group(1)
            filepath = os.path.join(CHAT_DIR, fname)

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = [l.strip() for l in f.readlines() if l.strip()]
            except Exception:
                continue

            if len(lines) < 4 or not lines[0].startswith('v2|'):
                continue

            parts = lines[0].split('|')
            if len(parts) < 3:
                continue

            # ★ 双路径匹配：接收方哈希 || 发送方公钥哈希
            sender_pub = parts[1] if len(parts) >= 2 else ''
            sender_hash = hashlib.sha256(sender_pub.encode()).hexdigest()[:16] if sender_pub else ''

            if fhash not in valid_hashes and sender_hash not in valid_sender_hashes:
                continue

            # 解析服务器时间（第4行）
            admin_parts = lines[3].split('|', 1)
            server_time = admin_parts[1].strip() if len(admin_parts) >= 2 else ''

            # 按 since 过滤
            if since and server_time <= since:
                continue

            messages.append({
                'filename': fname,
                'receiver_hash': fhash,
                'sender_pub': sender_pub,
                'iv': parts[2] if len(parts) >= 3 else '',
                'wrapped_key': lines[1],
                'aes_content': lines[2],
                'admin_ip': admin_parts[0].strip(),
                'server_time': server_time,
                'time': server_time
            })
    except Exception:
        pass
    # 限制返回数量（最新50条）
    messages.sort(key=lambda x: x.get('time', ''))
    if len(messages) > 50:
        messages = messages[-50:]

    return jsonify({
        "messages": messages,
        "server_time": datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')
    })

# ═══════════════════════════════════════════════════════════
# 17.5 聊天举报 / 撤回 / 回复
# ═══════════════════════════════════════════════════════════
@app.route('/api/chat/report', methods=['POST'])
@require_captcha
@require_csrf
def chat_report():
    """接收方举报消息"""
    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)
    try:
        allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
        if not allowed:
            return rate_limit_json({"error": f"操作过于频繁，请 {remaining} 秒后再试"}, 429, in_wl, block_until)

        data = request.get_json(silent=True) or {}
        filename = (data.get('filename') or '').strip()
        reporter_pub = (data.get('reporter_pub') or '').strip()
        aes_key_enc = (data.get('aes_key_enc') or '').strip()
        reason_enc = (data.get('reason_enc') or '').strip()

        if not all([filename, reporter_pub, aes_key_enc, reason_enc]):
            return rate_limit_json({"error": "数据不完整"}, 400, in_wl, block_until)

        # 校验文件名格式
        if not re.match(r'^[a-f0-9]{16}_\d{4}\.txt$', filename):
            return rate_limit_json({"error": "文件名格式无效"}, 400, in_wl, block_until)

        # 校验 reporter_pub 基本格式
        if not (reporter_pub.startswith('-----BEGIN') and 'PUBLIC KEY' in reporter_pub):
            return rate_limit_json({"error": "举报者公钥格式无效"}, 400, in_wl, block_until)

        # 检查消息文件是否存在
        filepath = safe_resolve(CHAT_DIR, filename)
        if not filepath or not os.path.isfile(filepath):
            return rate_limit_json({"error": "消息不存在"}, 404, in_wl, block_until)

        # 检查是否已被同一人举报（按 reporter_pub 哈希去重）
        reporter_hash = hashlib.sha256(reporter_pub.encode()).hexdigest()[:16]
        try:
            for fname in os.listdir(REPORT_DIR):
                if not fname.endswith('.json'):
                    continue
                try:
                    with open(os.path.join(REPORT_DIR, fname), 'r', encoding='utf-8') as f:
                        existing = json.load(f)
                    if existing.get('filename') == filename and existing.get('reporter_hash') == reporter_hash and existing.get('status') != 'resolved':
                        return rate_limit_json({"error": "您已经举报过这条消息，请勿重复举报"}, 429, in_wl, block_until)
                except Exception:
                    continue
        except Exception:
            pass

        report_id = get_report_seq()
        report = {
            'id': f'report_{report_id:04d}',
            'filename': filename,
            'reporter_pub': reporter_pub,
            'reporter_hash': reporter_hash,
            'aes_key_enc': aes_key_enc,
            'reason_enc': reason_enc,
            'server_time': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
            'reporter_ip': encrypt_ip(ip),
            'status': 'pending',
            'admin_reply': ''
        }

        atomic_write(os.path.join(REPORT_DIR, f'report_{report_id:04d}.json'),
                     json.dumps(report, ensure_ascii=False))

        block_until = set_rate_limit_after(ip)
        return rate_limit_json({"status": "ok", "report_id": report['id']}, 200, in_wl, block_until)
    finally:
        release_processing_lock(ip)


import hmac as _hmac

def _sign_revoke_token(filename, nonce):
    """生成撤回 token：HMAC-SHA256(filename|nonce|expire)"""
    expire = int(time.time()) + 120
    payload = f"{filename}|{nonce}|{expire}"
    sig = _hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    token_b64 = base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()
    return token_b64

def _verify_revoke_token(token_b64):
    """验证撤回 token，返回 (filename, nonce) 或 (None, None)"""
    try:
        payload_sig = base64.urlsafe_b64decode(token_b64.encode()).decode()
        parts = payload_sig.rsplit('|', 1)
        if len(parts) != 2:
            return None, None
        payload, sig = parts
        expected_sig = _hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected_sig):
            return None, None
        payload_parts = payload.split('|')
        if len(payload_parts) != 3:
            return None, None
        filename, nonce, expire_str = payload_parts
        if int(expire_str) < time.time():
            return None, None
        return filename, nonce
    except Exception:
        return None, None


@app.route('/api/chat/revoke/challenge', methods=['POST'])
@require_captcha
@require_csrf
def chat_revoke_challenge():
    """撤回第一步：请求挑战（用文件中发送方公钥加密随机数）"""
    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)
    try:
        allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
        if not allowed:
            return rate_limit_json(
                {"error": f"操作过于频繁，请 {remaining} 秒后再试"},
                429, in_wl, block_until
            )

        data = request.get_json(silent=True) or {}
        filename   = (data.get('filename')   or '').strip()
        sender_pub = (data.get('sender_pub') or '').strip()

        if not filename or not sender_pub:
            return rate_limit_json({"error": "数据不完整"}, 400, in_wl, block_until)

        if not re.match(r'^[a-f0-9]{16}_\d{4}\.txt$', filename):
            return rate_limit_json({"error": "文件名格式无效"}, 400, in_wl, block_until)

        if not (sender_pub.startswith('-----BEGIN') and 'PUBLIC KEY' in sender_pub):
            return rate_limit_json({"error": "发送方公钥格式无效"}, 400, in_wl, block_until)

        if is_message_reported(filename):
            return rate_limit_json({"error": "该消息已被举报，无法撤回"}, 403, in_wl, block_until)

        filepath = safe_resolve(CHAT_DIR, filename)
        if not filepath or not os.path.isfile(filepath):
            return rate_limit_json({"error": "消息不存在"}, 404, in_wl, block_until)

        # 读取文件第一行，比对 sender_pub
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
        except Exception:
            return rate_limit_json({"error": "读取消息失败"}, 500, in_wl, block_until)

        if not first_line.startswith('v2|'):
            return rate_limit_json({"error": "消息格式异常"}, 500, in_wl, block_until)

        parts = first_line.split('|')
        stored_sender_pub = parts[1] if len(parts) >= 2 else ''

        req_pub = sender_pub.replace('\n', '').replace('\r', '').strip()
        sto_pub = stored_sender_pub.replace('\n', '').replace('\r', '').strip()
        if req_pub != sto_pub:
            return rate_limit_json(
                {"error": "只有消息发送方可以撤回此消息"},
                403, in_wl, block_until
            )

        # 生成挑战 nonce，用发送方公钥加密
        nonce = secrets.token_urlsafe(32)
        try:
            pub_for_encrypt = sender_pub
            pem_match = re.match(
                r'(-----BEGIN [^-]+-----)\s*([\s\S]*?)\s*(-----END [^-]+-----)',
                sender_pub
            )
            if pem_match:
                body = re.sub(r'[\r\n\s]+', '', pem_match.group(2))
                lines_64 = [body[i:i+64] for i in range(0, len(body), 64)]
                pub_for_encrypt = pem_match.group(1) + '\n' + '\n'.join(lines_64) + '\n' + pem_match.group(3)

            pub_key = RSA.importKey(pub_for_encrypt)
            challenge = base64.b64encode(
                PKCS1_v1_5.new(pub_key).encrypt(nonce.encode())
            ).decode()
        except Exception:
            return rate_limit_json({"error": "无法加密挑战（公钥无效）"}, 500, in_wl, block_until)

        # ★ 生成 HMAC 签名的 token（替代 session）
        revoke_token = _sign_revoke_token(filename, nonce)

        return rate_limit_json(
            {"challenge": challenge, "filename": filename, "token": revoke_token},
            200, in_wl, block_until
        )
    finally:
        release_processing_lock(ip)


@app.route('/api/chat/revoke', methods=['POST'])
@require_captcha
@require_csrf
def chat_revoke():
    """撤回第二步：验证挑战答案，删除文件"""
    ip = get_client_ip()
    if not acquire_processing_lock(ip):
        return rate_limit_json({"error": "请求处理中，请勿重复提交"}, 429, False, 0)
    try:
        allowed, in_wl, block_until, remaining = check_rate_limit_before(ip)
        if not allowed:
            return rate_limit_json(
                {"error": f"操作过于频繁，请 {remaining} 秒后再试"},
                429, in_wl, block_until
            )

        data = request.get_json(silent=True) or {}
        filename = (data.get('filename') or '').strip()
        answer   = (data.get('answer')   or '').strip()
        token    = (data.get('token')    or '').strip()

        if not filename or not answer or not token:
            return rate_limit_json({"error": "数据不完整"}, 400, in_wl, block_until)

        if not re.match(r'^[a-f0-9]{16}_\d{4}\.txt$', filename):
            return rate_limit_json({"error": "文件名格式无效"}, 400, in_wl, block_until)

        # ★ 验证 HMAC token（无状态，不依赖 session）
        token_filename, stored_nonce = _verify_revoke_token(token)
        if not token_filename or not stored_nonce:
            return rate_limit_json({"error": "挑战已过期或无效，请重新请求"}, 400, in_wl, block_until)

        if token_filename != filename:
            return rate_limit_json({"error": "挑战与目标消息不匹配"}, 400, in_wl, block_until)

        if answer != stored_nonce:
            return rate_limit_json(
                {"error": "私钥验证失败，无权撤回此消息"},
                403, in_wl, block_until
            )

        # 已被举报则不可撤回
        if is_message_reported(filename):
            return rate_limit_json({"error": "该消息已被举报，无法撤回"}, 403, in_wl, block_until)

        filepath = safe_resolve(CHAT_DIR, filename)
        if not filepath or not os.path.isfile(filepath):
            return rate_limit_json({"error": "消息不存在"}, 404, in_wl, block_until)

        os.remove(filepath)

        block_until = set_rate_limit_after(ip)
        return rate_limit_json({"status": "ok", "revoked": filename}, 200, in_wl, block_until)
    finally:
        release_processing_lock(ip)

@app.route('/api/chat/report/status', methods=['GET'])
def chat_report_status():
    """举报者查询举报处理状态（用 reporter 公钥哈希）"""
    rl = check_rate_limit('read')
    if rl:
        return rl

    reporter_hash = (request.args.get('reporter_hash') or '').strip().lower()
    if not safe_chat_hash(reporter_hash):
        return jsonify({"reports": []})

    results = []
    try:
        for fname in sorted(os.listdir(REPORT_DIR), reverse=True):
            if not fname.endswith('.json'):
                continue
            try:
                with open(os.path.join(REPORT_DIR, fname), 'r', encoding='utf-8') as f:
                    report = json.load(f)
                if report.get('reporter_hash') == reporter_hash:
                    results.append({
                        'report_id': report.get('id', ''),
                        'filename': report.get('filename', ''),
                        'server_time': report.get('server_time', ''),
                        'status': report.get('status', 'pending'),
                        'admin_reply': report.get('admin_reply', '')
                    })
            except Exception:
                continue
    except Exception:
        pass

    return jsonify({"reports": results[:20]})
@app.route('/api/admin/chat/messages', methods=['GET'])
@require_csrf
@require_private_key
def admin_chat_messages():
    """管理员查看聊天消息元数据（不含可解密内容）"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    filter_hash = request.args.get('hash', '').strip().lower()
    filter_filename = request.args.get('filename', '').strip()

    if filter_filename:
        # 查看单个文件详情
        path = safe_resolve(CHAT_DIR, filter_filename)
        if not path or not os.path.isfile(path):
            return jsonify({'messages': []})
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
            if len(lines) < 4 or not lines[0].startswith('v2|'):
                return jsonify({'messages': []})
            parts = lines[0].split('|')
            admin_parts = lines[3].split('|', 1)
            m = re.match(r'^([a-f0-9]{16})_(\d+)\.txt$', filter_filename)
            return jsonify({'messages': [{
                'filename': filter_filename,
                'receiver_hash': m.group(1) if m else '',
                'sender_pub': parts[1] if len(parts) >= 2 else '',
                'iv': parts[2] if len(parts) >= 3 else '',
                'wrapped_key': lines[1],
                'aes_content': lines[2],
                'admin_ip': admin_parts[0].strip() if len(admin_parts) >= 1 else '',
                'server_time': admin_parts[1].strip() if len(admin_parts) >= 2 else ''
            }]})
        except Exception:
            return jsonify({'messages': []})

    messages = []
    try:
        for fname in sorted(os.listdir(CHAT_DIR), reverse=True):
            if not fname.endswith('.txt'):
                continue
            m = re.match(r'^([a-f0-9]{16})_(\d+)\.txt$', fname)
            if not m:
                continue
            fhash = m.group(1)
            if filter_hash and fhash != filter_hash:
                continue

            filepath = os.path.join(CHAT_DIR, fname)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    # 只读第一行和最后一行，提高性能
                    f.seek(0)
                    lines = f.readlines()
                    if len(lines) < 4:
                        continue
                    last_line = lines[3].strip() if len(lines) > 3 else ''
            except Exception:
                continue

            if not first_line.startswith('v2|'):
                continue
            parts = first_line.split('|')
            admin_parts = last_line.split('|', 1)

            messages.append({
                'filename': fname,
                'receiver_hash': fhash,
                'sender_pub': parts[1] if len(parts) >= 2 else '',
                'admin_ip': admin_parts[0].strip() if len(admin_parts) >= 1 else '',
                'server_time': admin_parts[1].strip() if len(admin_parts) >= 2 else ''
            })

            if len(messages) >= 200:
                break
    except Exception:
        pass

    return jsonify({'messages': messages})


@app.route('/api/admin/chat/delete/<filename>', methods=['POST'])
@require_csrf
@require_private_key
def admin_chat_delete(filename):
    """管理员删除聊天文件"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403
    path = safe_resolve(CHAT_DIR, filename)
    if not path or not os.path.isfile(path):
        return jsonify({'error': '文件不存在'}), 404
    os.remove(path)
    return jsonify({'ok': True})
@app.route('/api/admin/chat/reports', methods=['GET'])
@require_csrf
@require_private_key
def admin_chat_reports():
    """管理员查看所有举报"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    status_filter = request.args.get('status', '').strip()
    results = []
    try:
        for fname in sorted(os.listdir(REPORT_DIR), reverse=True):
            if not fname.endswith('.json'):
                continue
            try:
                with open(os.path.join(REPORT_DIR, fname), 'r', encoding='utf-8') as f:
                    report = json.load(f)
            except Exception:
                continue

            if status_filter and report.get('status') != status_filter:
                continue

            results.append({
                'report_id': report.get('id', ''),
                'filename': report.get('filename', ''),
                'reporter_pub': report.get('reporter_pub', ''),
                'reporter_hash': report.get('reporter_hash', ''),
                'aes_key_enc': report.get('aes_key_enc', ''),
                'reason_enc': report.get('reason_enc', ''),
                'server_time': report.get('server_time', ''),
                'reporter_ip': report.get('reporter_ip', ''),
                'status': report.get('status', 'pending'),
                'admin_reply': report.get('admin_reply', '')
            })

            if len(results) >= 100:
                break
    except Exception:
        pass

    return jsonify({'reports': results})


@app.route('/api/admin/chat/reports/<report_id>', methods=['DELETE'])
@require_csrf
@require_private_key
def admin_chat_delete_report(report_id):
    """管理员删除举报（标记为已处理）"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    safe_id = re.sub(r'[^\w\-]', '', report_id)
    if not safe_id or safe_id in ('.', '..'):
        return jsonify({'error': '无效ID'}), 400

    filepath = os.path.join(REPORT_DIR, f'{safe_id}.json')
    if not os.path.isfile(filepath):
        return jsonify({'error': '举报不存在'}), 404

    data = request.get_json(silent=True) or {}
    if data.get('resolve_only'):
        with _file_lock:
            with open(filepath, 'r', encoding='utf-8') as f:
                report = json.load(f)
            report['status'] = 'resolved'
            atomic_write_unlocked(filepath, json.dumps(report, ensure_ascii=False))
        return jsonify({'ok': True})

    os.remove(filepath)
    return jsonify({'ok': True})


@app.route('/api/admin/chat/reports/<report_id>/reply', methods=['POST'])
@require_csrf
@require_private_key
def admin_chat_reply(report_id):
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    safe_id = re.sub(r'[^\w\-]', '', report_id)
    if not safe_id or safe_id in ('.', '..'):
        return jsonify({'error': '无效ID'}), 400

    filepath = os.path.join(REPORT_DIR, f'{safe_id}.json')
    if not os.path.isfile(filepath):
        return jsonify({'error': '举报不存在'}), 404

    data = request.get_json(silent=True) or {}
    reply = (data.get('reply') or '').strip()
    if not reply:
        return jsonify({'error': '回复内容不能为空'}), 400
    if len(reply) > 2048:
        return jsonify({'error': '回复过长'}), 400

    with _file_lock:
        with open(filepath, 'r', encoding='utf-8') as f:
            report = json.load(f)
        report['admin_reply'] = reply
        report['status'] = 'reviewed'
        report['reply_time'] = datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')
        atomic_write_unlocked(filepath, json.dumps(report, ensure_ascii=False))

    return jsonify({'ok': True})
@app.route('/api/admin/chat/message/<filename>', methods=['GET'])
@require_csrf
@require_private_key
def admin_get_message_raw(filename):
    """管理员获取单条消息的原始密文（用于解密查看）"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    path = safe_resolve(CHAT_DIR, filename)
    if not path or not os.path.isfile(path):
        return jsonify({'error': '消息不存在'}), 404

    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        if len(lines) < 4 or not lines[0].startswith('v2|'):
            return jsonify({'error': '消息格式异常'}), 500

        parts = lines[0].split('|')
        admin_parts = lines[3].split('|', 1)
        return jsonify({
            'filename': filename,
            'sender_pub': parts[1] if len(parts) >= 2 else '',
            'iv': parts[2] if len(parts) >= 3 else '',
            'wrapped_key': lines[1],
            'aes_content': lines[2],
            'admin_ip': admin_parts[0].strip(),
            'server_time': admin_parts[1].strip() if len(admin_parts) >= 2 else ''
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/admin/chat/retention', methods=['GET', 'POST'])
@require_csrf
@require_private_key
def chat_retention():
    """管理员配置聊天消息保留时长（小时），0=不自动删除"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403
    if request.method == 'GET':
        return jsonify({'hours': load_chat_retention()})
    data = request.get_json(silent=True) or {}
    try:
        hours = int(data.get('hours', '0'))
        if hours < 0:
            return jsonify({'error': '小时数不能为负数'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': '请输入有效整数'}), 400
    atomic_write(CHAT_RETENTION_FILE, str(hours))
    return jsonify({'ok': True, 'hours': hours})
# ═══════════════════════════════════════════════════════════
# 18. 数据导入导出（全量备份/恢复）
# ═══════════════════════════════════════════════════════════
import zipfile
import io
import shutil

# 临时提高上传大小限制（仅用于导入）
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

@app.route('/api/admin/export-data', methods=['GET'])
@require_csrf
@require_private_key
def export_data():
    """导出 /data 目录为 ZIP 文件"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    # 创建内存中的 ZIP 文件
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        data_dir = DATA_DIR
        if not os.path.exists(data_dir):
            return jsonify({'error': '数据目录不存在'}), 404

        for root, dirs, files in os.walk(data_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # 计算相对路径（相对于 DATA_DIR）
                arcname = os.path.relpath(file_path, data_dir)
                zf.write(file_path, arcname)

    zip_buffer.seek(0)
    return Response(
        zip_buffer.getvalue(),
        mimetype='application/zip',
        headers={
            'Content-Disposition': f'attachment; filename=backup_{datetime.now(CST).strftime("%Y%m%d_%H%M%S")}.zip'
        }
    )

def safe_extract(zip_file, extract_dir):
    """
    安全解压 ZIP 文件，防止路径遍历攻击。
    - 拒绝包含 '..' 或绝对路径的条目。
    - 确保所有解压目标都在 extract_dir 之内。
    """
    extract_dir = os.path.realpath(extract_dir)
    for member in zip_file.infolist():
        # 拒绝绝对路径或包含 '..' 的路径
        if member.filename.startswith('/') or '..' in member.filename.split('/'):
            raise Exception(f'非法路径: {member.filename}')
        target = os.path.realpath(os.path.join(extract_dir, member.filename))
        if not target.startswith(extract_dir + os.sep):
            raise Exception(f'路径遍历检测: {member.filename}')
    # 所有条目通过检查，执行解压
    zip_file.extractall(extract_dir)

@app.route('/api/admin/import-data', methods=['POST'])
@require_csrf
@require_private_key
def import_data():
    """导入 ZIP 文件并覆盖 /data 目录"""
    if not is_admin():
        return jsonify({'error': '未授权'}), 403

    # 检查是否有文件上传
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '文件名为空'}), 400
    if not file.filename.lower().endswith('.zip'):
        return jsonify({'error': '仅支持 ZIP 文件'}), 400

    try:
        # 读取上传的文件内容
        zip_data = file.read()
        zip_buffer = io.BytesIO(zip_data)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # 先验证 ZIP 是否有效
            if zf.testzip() is not None:
                return jsonify({'error': 'ZIP 文件损坏'}), 400

            # 清空当前 DATA_DIR（保留目录本身）
            data_dir = DATA_DIR
            if os.path.exists(data_dir):
                # 删除所有子文件和子目录，但保留 data_dir 本身
                for item in os.listdir(data_dir):
                    item_path = os.path.join(data_dir, item)
                    if os.path.isfile(item_path) or os.path.islink(item_path):
                        os.unlink(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)

            # 安全解压（防止路径遍历）
            try:
                safe_extract(zf, data_dir)
            except Exception as e:
                return jsonify({'error': f'解压失败: {str(e)}'}), 400

        return jsonify({'ok': True, 'message': '数据已成功导入'})
    except zipfile.BadZipFile:
        return jsonify({'error': '无效的 ZIP 文件'}), 400
    except Exception as e:
        return jsonify({'error': f'导入失败: {str(e)}'}), 500

if __name__ == '__main__':
    print(f"[CONFIG] SESSION_COOKIE_SECURE = {app.config['SESSION_COOKIE_SECURE']}")
    print(f"[CONFIG] TRUSTED_PROXIES = {TRUSTED_PROXIES}")
    print(f"[CONFIG] RSA_PUB exists = {os.path.exists(RSA_PUB)}")
    app.run(debug=False, host='0.0.0.0', port=5033)