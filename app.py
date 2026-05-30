python -m pip install Flask
from flask import Flask, request, render_template, jsonify, session
import os, re, glob, base64, json, secrets, time, hashlib, threading, tempfile, shutil
from collections import OrderedDict
from functools import wraps
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# === 1. 密钥与会话安全配置 ===
SECRET_KEY_ENV = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY_ENV:
    temp_key = secrets.token_hex(64)
    print(f"\n[⚠️ 安全警告] 未检测到 FLASK_SECRET_KEY！\n[🔑 临时密钥] {temp_key}\n请将其写入 .env 文件，否则重启后会话失效。\n")
    app.secret_key = temp_key
else:
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
MSG_DIR = os.path.join(BASE_DIR, '留言')
REPLY_DIR = os.path.join(BASE_DIR, '回复')
QUN_DIR = os.path.join(BASE_DIR, '群')
VOTE_DIR = os.path.join(BASE_DIR, 'vote_data')
RSA_PUB = os.path.join(BASE_DIR, 'gongyao.txt')
UNDER_FILE = os.path.join(BASE_DIR, 'under.txt')
CHAT_FILE = os.path.join(QUN_DIR, 'chat_data.json')
PERM_FILE = os.path.join(QUN_DIR, 'permission.txt')
BLACK_FILE = os.path.join(BASE_DIR, 'black.txt')
WHITE_FILE = os.path.join(BASE_DIR, 'white.txt')
LOG_FILE = os.path.join(BASE_DIR, 'log.txt')

for d in [MSG_DIR, REPLY_DIR, QUN_DIR, VOTE_DIR]:
    os.makedirs(d, exist_ok=True)
for f, v in [(UNDER_FILE, 'under construction'), (PERM_FILE, '0'), (BLACK_FILE, ''), (WHITE_FILE, '')]:
    if not os.path.exists(f):
        open(f, 'w', encoding='utf-8').write(v)
if not os.path.exists(CHAT_FILE):
    json.dump([], open(CHAT_FILE, 'w', encoding='utf-8'))

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
        chat = json.load(open(CHAT_FILE, 'r', encoding='utf-8'))
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
            return open(PERM_FILE, 'r').read().strip()
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


# === 5. 核心工具函数 ===
def get_client_ip():
    direct_ip = request.remote_addr or '127.0.0.1'
    if 'any' in [p.lower() for p in TRUSTED_PROXIES]:
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            return xff.split(',')[0].strip()
        return direct_ip
    if TRUSTED_PROXIES and direct_ip in TRUSTED_PROXIES:
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            return xff.split(',')[0].strip()
    return direct_ip


def get_fp():
    ua = request.headers.get('User-Agent', '')
    return hashlib.sha256(f"{get_client_ip()}|{ua}".encode()).hexdigest()[:16]


def is_admin():
    return session.get('admin') is True


def load_blacklist():
    try:
        return set(line.strip() for line in open(BLACK_FILE, 'r', encoding='utf-8') if line.strip())
    except Exception:
        return set()


def load_whitelist():
    try:
        return set(line.strip() for line in open(WHITE_FILE, 'r', encoding='utf-8') if line.strip())
    except Exception:
        return set()


def load_chat():
    with _file_lock:
        return json.load(open(CHAT_FILE, 'r', encoding='utf-8'))


def save_chat(data):
    atomic_write(CHAT_FILE, json.dumps(data, ensure_ascii=False))


def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


# === 6. 速率限制模块 ===
RATE_LIMIT_WRITE = 8
RATE_LIMIT_READ = 56
RATE_MAX_ENTRIES = 10000
_rate_counters = OrderedDict()
_rate_lock = threading.Lock()


def _get_minute_bucket():
    return int(time.time() // 60) * 60


def _is_whitelisted(ip):
    return ip in load_whitelist()


def _log_exceed(ip, bucket, write_count, read_count):
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bucket))
    line = f"{ts} | {ip} | write={write_count} read={read_count}\n"
    try:
        with _file_lock:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(line)
    except Exception:
        pass


def check_rate_limit(limit_type):
    ip = get_client_ip()
    if _is_whitelisted(ip):
        return None
    bucket = _get_minute_bucket()
    key = (ip, bucket)
    limit = RATE_LIMIT_WRITE if limit_type == 'write' else RATE_LIMIT_READ
    with _rate_lock:
        prev_bucket = bucket - 60
        while _rate_counters:
            oldest_key = next(iter(_rate_counters))
            if oldest_key[1] < prev_bucket:
                _rate_counters.pop(oldest_key)
            else:
                break
        while len(_rate_counters) >= RATE_MAX_ENTRIES:
            _rate_counters.popitem(last=False)
        counts = _rate_counters.setdefault(key, {'write': 0, 'read': 0})
        _rate_counters.move_to_end(key)
        counts[limit_type] += 1
        current_count = counts[limit_type]
        if current_count > limit:
            _log_exceed(ip, bucket, counts['write'], counts['read'])
            remaining = 60 - int(time.time()) % 60
            return jsonify({'error': f'请求过于频繁，请{remaining}秒后重试'}), 429
    return None


# === 7. 安全中间件 ===
@app.before_request
def security_checks():
    if get_client_ip() in load_blacklist():
        return "IP已被封禁，拒绝访问", 403
    if session.get('admin'):
        stored = session.get('fp')
        if stored and stored != get_fp():
            session.clear()


@app.after_request
def secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'none'"
    )
    return response


def require_csrf(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            token = session.get('csrf_token')
            header = request.headers.get('X-CSRF-Token')
            if not token or token != header:
                return jsonify({'error': 'CSRF 校验失败'}), 403
        return f(*args, **kwargs)
    return decorated


def require_private_key(f):
    """装饰器：要求 Session 中已通过私钥校验"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_has_key'):
            return jsonify({'error': '私钥未校验'}), 403
        return f(*args, **kwargs)
    return decorated


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
    if rl: return rl
    plaintext = request.form.get('plaintext')
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


# === 9. 路由：基础与留言 ===
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
def index():
    if request.method == 'POST':
        rl = check_rate_limit('write')
        if rl: return rl
        data = request.get_json()
        if not all(data.get(k) for k in ('rsa_key', 'aes_msg', 'iv', 'meta_msg')):
            return "数据不完整", 400
        rsa_key = data['rsa_key'].replace('\n', '').replace('\r', '').strip()
        iv = data['iv'].replace('\n', '').replace('\r', '').strip()
        meta_msg = data['meta_msg'].replace('\n', '').replace('\r', '').strip()
        aes_msg = data['aes_msg'].replace('\n', '').replace('\r', '').strip()
        content = f"{rsa_key}|{iv}\n{meta_msg}\n{aes_msg}"
        with _file_lock:
            seq = get_seq_unlocked()
            atomic_write_unlocked(os.path.join(MSG_DIR, f"留言_{seq}.txt"), content)
        return {"status": "ok"}, 200
    return render_template('login.html')


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
                lines = fh.readlines()
                if len(lines) < 3: continue
                msgs.append({
                    'file': os.path.basename(f),
                    'seq': re.search(r'(\d+)', os.path.basename(f)).group(1),
                    'rsa_iv': lines[0].strip(),
                    'meta_enc': lines[1].strip(),
                    'content_enc': ''.join(lines[2:]).strip()
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
    for f in glob.glob(os.path.join(REPLY_DIR, '回复_*.txt')):
        m = re.search(r'(\d+)', os.path.basename(f))
        if not m: continue
        try:
            with open(f, encoding='utf-8') as fh:
                lines = fh.readlines()
                if len(lines) >= 2:
                    reps.append({'seq': m.group(1), 'iv': lines[0].strip(), 'aes_msg': ''.join(lines[1:]).strip()})
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
                lines = fh.readlines()
                if len(lines) < 3: continue
                rsa_iv = lines[0].strip()
                parts = rsa_iv.split('|')
                iv = parts[1] if len(parts) >= 2 else ''
                meta_msg = lines[1].strip()
                aes_msg = ''.join(lines[2:]).strip()
                msgs.append({
                    'seq': m.group(1),
                    'iv': iv,
                    'meta_msg': meta_msg,
                    'aes_msg': aes_msg
                })
        except Exception:
            continue
    return jsonify(msgs)


@app.route('/api/reply', methods=['POST'])
@require_csrf
def save_reply():
    if not is_admin(): return "未授权", 403
    data = request.get_json()
    if not data.get('seq'): return "缺少序号", 400
    content = f"{data['iv']}\n{data['aes_msg']}"
    atomic_write(os.path.join(REPLY_DIR, f"回复_{data['seq']}.txt"), content)
    return "ok"


@app.route('/admin/delete/<filename>', methods=['POST'])
@require_csrf
def delete_msg(filename):
    if not is_admin(): return "未授权", 403
    path = safe_resolve(MSG_DIR, filename)
    if not path or not os.path.isfile(path): return "无效文件", 400
    os.remove(path)
    if m := re.search(r'(\d+)', os.path.basename(path)):
        r_path = safe_resolve(REPLY_DIR, f"回复_{m.group(1)}.txt")
        if r_path and os.path.isfile(r_path): os.remove(r_path)
    return "ok"


@app.route('/admin/delete_reply/<seq>', methods=['POST'])
@require_csrf
def delete_reply(seq):
    if not is_admin(): return "未授权", 403
    if not re.match(r'^\d+$', str(seq)): return "无效序号", 400
    path = safe_resolve(REPLY_DIR, f"回复_{seq}.txt")
    if not path or not os.path.isfile(path): return "无效文件", 400
    os.remove(path)
    return "ok"


@app.route('/api/footer', methods=['POST'])
@require_csrf
def update_footer():
    if not is_admin(): return "未授权", 403
    atomic_write(UNDER_FILE, request.form.get('content', ''))
    return "ok"


@app.route('/api/blacklist', methods=['GET', 'POST'])
@require_csrf
def manage_blacklist():
    if not is_admin(): return "未授权", 403
    bl = load_blacklist()
    if request.method == 'GET': return jsonify(list(bl))
    data = request.get_json()
    ip = data.get('ip', '').strip()
    if not ip: return "IP无效", 400
    if data.get('action') == 'add': bl.add(ip)
    elif data.get('action') == 'remove': bl.discard(ip)
    atomic_write(BLACK_FILE, '\n'.join(bl) + '\n' if bl else '')
    return "ok"


@app.route('/api/whitelist', methods=['GET', 'POST'])
@require_csrf
def manage_whitelist():
    if not is_admin(): return "未授权", 403
    rl = check_rate_limit('read')
    if rl: return rl
    wl = load_whitelist()
    if request.method == 'GET': return jsonify(list(wl))
    data = request.get_json()
    ip = data.get('ip', '').strip()
    if not ip: return "IP无效", 400
    if data.get('action') == 'add': wl.add(ip)
    elif data.get('action') == 'remove': wl.discard(ip)
    atomic_write(WHITE_FILE, '\n'.join(sorted(wl)) + '\n' if wl else '')
    return "ok"


# === 12. 路由：群聊 ===
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
    normal = [m for m in chat if not m.get('pinned')]
    pinned = [m for m in chat if m.get('pinned')]
    ordered = normal + pinned
    return jsonify([
        {'nick': m['nick'], 'time': m['time'], 'content': m['content'], 'pinned': bool(m.get('pinned'))}
        for m in ordered
    ])


@app.route('/api/qun', methods=['POST'])
def post_qun():
    rl = check_rate_limit('write')
    if rl: return rl
    if read_perm_file() == '1': return "已开启全体禁言", 403
    data = request.get_json()
    if not data.get('nick') or not data.get('content'): return "数据不完整", 400
    if data['nick'].strip().lower() == 'admin': return "禁止使用 admin 作为昵称", 400
    msg = {
        'nick': data['nick'][:32],
        'time': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
        'ip': get_client_ip(),
        'content': data['content'][:2048],
        'pinned': False
    }
    def updater(chat):
        chat.append(msg)
    atomic_chat_update(updater)
    return {"status": "ok"}, 200


@app.route('/admin/qun')
def admin_qun_page():
    return render_template('admin_qun.html')


@app.route('/api/admin/qun', methods=['GET'])
@require_csrf
def get_admin_qun():
    if not is_admin(): return "未授权", 403
    chat = load_chat()
    return jsonify([
        {'nick': m['nick'], 'time': m['time'], 'content': m['content'], 'ip': m.get('ip', ''), 'pinned': bool(m.get('pinned'))}
        for m in chat
    ])


@app.route('/api/admin/qun/delete/<int:index>', methods=['POST'])
@require_csrf
def delete_qun_msg(index):
    if not is_admin(): return "未授权", 403
    def updater(chat):
        if 0 <= index < len(chat):
            chat.pop(index)
    atomic_chat_update(updater)
    return "ok"


@app.route('/api/admin/qun/announce', methods=['POST'])
@require_csrf
def send_announce():
    if not is_admin(): return "未授权", 403
    data = request.get_json()
    content = data.get('content', '').strip()
    if not content: return "内容不能为空", 400
    msg = {
        'nick': 'admin',
        'time': datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S'),
        'ip': get_client_ip(),
        'content': content,
        'pinned': False
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


# ═══════════════════════════════════════════════════════════
# 🆕 13. 路由：投票系统（v2 — 允许修改 + 编辑令牌）
# ═══════════════════════════════════════════════════════════

# ── 用户端页面 ──
@app.route('/vote')
def vote_page():
    return render_template('vote.html')


# ── 用户 API：列出所有投票 ──
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
                'minSelect': cfg.get('minSelect', 1),     # ⬅ 新增
                'maxSelect': cfg.get('maxSelect', 1),     # ⬅ 新增
                'total_votes': len(vote_files),
                'created_at': cfg.get('created_at', '')
            })
        except Exception:
            continue
    return jsonify(polls)


# ── 用户 API：提交投票 ──
@app.route('/api/votes/<poll_id>', methods=['POST'])
def submit_vote(poll_id):
    rl = check_rate_limit('write')
    if rl:
        return rl

    poll_dir = safe_vote_dir(poll_id)
    if not poll_dir or not os.path.isdir(poll_dir):
        return "投票不存在", 404

    data = request.get_json()
    if not all(data.get(k) for k in ('rsa_key', 'aes_msg', 'iv', 'meta_msg')):
        return "数据不完整", 400

    rsa_key = data['rsa_key'].replace('\n', '').replace('\r', '').strip()
    iv = data['iv'].replace('\n', '').replace('\r', '').strip()
    meta_msg = data['meta_msg'].replace('\n', '').replace('\r', '').strip()
    aes_msg = data['aes_msg'].replace('\n', '').replace('\r', '').strip()
    edit_token = data.get('edit_token', '').strip() or secrets.token_urlsafe(24)

    content = f"{rsa_key}|{iv}\n{meta_msg}\n{aes_msg}\n{edit_token}"

    with _file_lock:
        seq = get_vote_seq_unlocked(poll_dir)
        atomic_write_unlocked(os.path.join(poll_dir, f"投票_{seq}.txt"), content)

    return jsonify({'status': 'ok', 'seq': seq, 'edit_token': edit_token}), 200


# ── 用户 API：修改自己的投票 ──
@app.route('/api/votes/<poll_id>/<int:seq>', methods=['PUT'])
def modify_vote(poll_id, seq):
    rl = check_rate_limit('write')
    if rl:
        return rl

    poll_dir = safe_vote_dir(poll_id)
    if not poll_dir or not os.path.isdir(poll_dir):
        return "投票不存在", 404

    filepath = safe_resolve(poll_dir, f"投票_{seq}.txt")
    if not filepath or not os.path.isfile(filepath):
        return "投票记录不存在", 404

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            old_lines = f.readlines()
        old_edit_token = old_lines[3].strip() if len(old_lines) >= 4 else ''
    except Exception:
        return "读取原投票失败", 500

    data = request.get_json()
    provided_token = data.get('edit_token', '').strip()

    if not old_edit_token or old_edit_token != provided_token:
        return "编辑令牌不匹配，无权修改此投票", 403

    if not all(data.get(k) for k in ('rsa_key', 'aes_msg', 'iv', 'meta_msg')):
        return "数据不完整", 400

    rsa_key = data['rsa_key'].replace('\n', '').replace('\r', '').strip()
    iv = data['iv'].replace('\n', '').replace('\r', '').strip()
    meta_msg = data['meta_msg'].replace('\n', '').replace('\r', '').strip()
    aes_msg = data['aes_msg'].replace('\n', '').replace('\r', '').strip()

    content = f"{rsa_key}|{iv}\n{meta_msg}\n{aes_msg}\n{old_edit_token}"

    with _file_lock:
        atomic_write_unlocked(filepath, content)

    return jsonify({'status': 'ok', 'seq': seq}), 200


# ── 管理端页面 ──
@app.route('/admin/vote')
def admin_vote_page():
    return render_template('admin_vote.html')


# ── 管理 API：创建投票 ──
@app.route('/api/admin/votes/create', methods=['POST'])
@require_csrf
@require_private_key
def create_vote():
    if not is_admin():
        return "未授权", 403

    data = request.get_json()
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


# ── 管理 API：获取投票数据 ──
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
    cfg = json.load(open(cfg_path, 'r', encoding='utf-8')) if os.path.exists(cfg_path) else {}

    votes = []
    for f in sorted(glob.glob(os.path.join(poll_dir, '投票_*.txt')),
                    key=lambda x: int(m.group(1)) if (m := re.search(r'(\d+)', os.path.basename(x))) else 0):
        m = re.search(r'(\d+)', os.path.basename(f))
        if not m:
            continue
        try:
            with open(f, encoding='utf-8') as fh:
                lines = fh.readlines()
                if len(lines) < 3:
                    continue
                rsa_iv = lines[0].strip()
                parts = rsa_iv.split('|')
                votes.append({
                    'seq': m.group(1),
                    'rsa_key': parts[0] if len(parts) >= 1 else '',
                    'iv': parts[1] if len(parts) >= 2 else '',
                    'meta_enc': lines[1].strip(),
                    'content_enc': lines[2].strip(),
                    'edit_token': lines[3].strip() if len(lines) >= 4 else ''
                })
        except Exception:
            continue

    return jsonify({
        'config': cfg,
        'votes': votes
    })


# ── 管理 API：删除单条投票 ──
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


if __name__ == '__main__':
    print(f"[CONFIG] SESSION_COOKIE_SECURE = {app.config['SESSION_COOKIE_SECURE']}")
    print(f"[CONFIG] TRUSTED_PROXIES = {TRUSTED_PROXIES}")
    print(f"[CONFIG] RSA_PUB exists = {os.path.exists(RSA_PUB)}")
    app.run(debug=False, host='0.0.0.0', port=5033)
