import asyncio
import random
import os
import json
import hashlib
import threading
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, session
from telethon import TelegramClient, errors
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.functions.messages import GetFullChatRequest, CheckChatInviteRequest, ImportChatInviteRequest
from telethon.tl.functions.phone import GetGroupCallRequest

app = Flask(__name__)

ADMIN_PASSWORD = "BhaiKaSecret123"
USERS_FILE = 'users.json'
ACCOUNTS_FILE = 'accounts.json'

state_lock = threading.Lock()
accounts = {}
pending = {}
logs = {}
users_list = []
login_attempts = {}
MAX_ATTEMPTS = 5
LOCK_SECONDS = 300


def get_secret_key():
    if os.path.exists('secret.key'):
        with open('secret.key') as f:
            return f.read().strip()
    key = os.urandom(32).hex()
    with open('secret.key', 'w') as f:
        f.write(key)
    return key

app.secret_key = get_secret_key()


def log(phone, tag, msg):
    ts = datetime.now().strftime('%H:%M:%S')
    line = "[" + ts + "] " + tag + " " + msg
    with state_lock:
        lg = logs.setdefault(phone, [])
        lg.append(line)
        if len(lg) > 500:
            del lg[:150]
    print("[" + phone + "] " + line)


# ---------------- SECURITY (HASHING) ----------------

def hash_val(plain):
    return 'sha256:' + hashlib.sha256(plain.encode()).hexdigest()


def verify_val(stored, plain):
    if stored and stored.startswith('sha256:'):
        return stored == hash_val(plain or '')
    return stored == plain


# ---------------- USER SYSTEM ----------------

def load_users_file():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                data = json.load(f)
                if isinstance(data, list) and data:
                    return data
        except Exception:
            pass
    return None


def save_users():
    with open(USERS_FILE, 'w') as f:
        json.dump(users_list, f, indent=2)


def migrate_users():
    changed = False
    for u in users_list:
        if not u['password'].startswith('sha256:'):
            u['password'] = hash_val(u['password'])
            changed = True
        if u.get('security_answer') and not u['security_answer'].startswith('sha256:'):
            u['security_answer'] = hash_val(u['security_answer'])
            changed = True
    if changed:
        save_users()
        print("Old passwords migrated to secure hash format")


def init_users():
    global users_list
    data = load_users_file()
    if data is None:
        users_list = [{
            'username': 'admin',
            'password': hash_val(ADMIN_PASSWORD),
            'role': 'admin',
            'active': True,
            'max_accounts': 9999,
            'max_targets': 9999
        }]
        save_users()
        print("Default admin created: admin / " + ADMIN_PASSWORD + "  (Change it from Admin Panel!)")
    else:
        users_list = data
        migrate_users()
        print(str(len(users_list)) + " panel user(s) loaded")


def get_user(username):
    for u in users_list:
        if u['username'] == username:
            return u
    return None


def effective_user():
    return session.get('view_as') or session.get('username') or ''


def is_admin_session():
    u = get_user(session.get('username', ''))
    return bool(u and u.get('role') == 'admin')


def can_touch(owner):
    if is_admin_session():
        return True
    return owner == effective_user()


def user_limits(username):
    u = get_user(username)
    if not u or u.get('role') == 'admin':
        return 9999, 9999
    return int(u.get('max_accounts', 5)), int(u.get('max_targets', 3))


# ---------------- ACCOUNT HELPERS ----------------

def default_config():
    return {
        'channel_link': '', 'targets': [], 'message': '',
        'max_users': 5, 'check_interval': 60,
        'delay_min': 60, 'delay_max': 120
    }

def load_accounts_json():
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE) as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []


def save_accounts_json():
    data = []
    for phone, a in accounts.items():
        item = {
            'label': a['label'], 'phone': a['phone'],
            'api_id': a['api_id'], 'api_hash': a['api_hash'],
            'config': a['config'], 'owner': a.get('owner', 'admin')
        }
        if a.get('username'):
            item['username'] = a['username']
        data.append(item)
    with open(ACCOUNTS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def load_sent_users(phone):
    s = set()
    fname = "sent_users_" + phone + ".txt"
    if os.path.exists(fname):
        with open(fname) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        s.add(int(line))
                    except ValueError:
                        pass
    return s


def save_sent_user(phone, uid):
    with open("sent_users_" + phone + ".txt", "a") as f:
        f.write(str(uid) + "\n")

def queue_file(phone):
    return "dm_queue_" + phone + ".txt"


def load_dm_queue(phone):
    ids = []
    if os.path.exists(queue_file(phone)):
        with open(queue_file(phone)) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ids.append(int(line))
                    except ValueError:
                        pass
    return ids


def add_to_queue(phone, uids):
    existing = set(load_dm_queue(phone))
    with open(queue_file(phone), "a") as f:
        for uid in uids:
            if uid not in existing:
                f.write(str(uid) + "\n")
                existing.add(uid)


def remove_from_queue(phone, uid):
    ids = load_dm_queue(phone)
    if uid in ids:
        ids.remove(uid)
        with open(queue_file(phone), "w") as f:
            for i in ids:
                f.write(str(i) + "\n")

def make_pending(phone):
    pending[phone] = {
        'otp_event': threading.Event(), 'otp_value': None,
        'twofa_event': threading.Event(), 'twofa_value': None,
        'waiting': None
    }


def unblock_pending(phone):
    p = pending.get(phone)
    if not p:
        return
    if p['waiting'] == 'otp':
        p['otp_event'].set()
    elif p['waiting'] == 'twofa':
        p['twofa_event'].set()


def status_state(a):
    s = a['status']
    if s in ('awaiting_otp', 'awaiting_2fa'):
        return 'waiting'
    if s == 'Stopping...':
        return 'stopping'
    if s.startswith('Failed'):
        return 'failed'
    if a['running']:
        return 'running'
    return 'idle'


async def wait_for_dashboard_value(phone, kind, timeout=600):
    p = pending.get(phone)
    if p is None:
        return None
    p[kind + '_event'].clear()
    p[kind + '_value'] = None
    p['waiting'] = kind
    loop = asyncio.get_event_loop()
    got = await loop.run_in_executor(None, p[kind + '_event'].wait, timeout)
    p['waiting'] = None
    if not got:
        return None
    return p[kind + '_value']


async def resolve_target(client, link, phone):
    if '/+' in link:
        invite_hash = link.split('/+')[-1]
        try:
            result = await client(ImportChatInviteRequest(invite_hash))
            entity = result.chats[0]
            log(phone, "OK", "Joined group: " + entity.title)
            return entity
        except errors.UserAlreadyParticipantError:
            try:
                info = await client(CheckChatInviteRequest(invite_hash))
                if hasattr(info, 'chat'):
                    return info.chat
            except Exception:
                pass
            log(phone, "WARN", "Group not found! Open the group in Telegram app once, then restart.")
            return None
        except errors.InviteHashExpiredError:
            log(phone, "FAIL", "Invite link has expired!")
            return None
        except errors.FloodWaitError as e:
            log(phone, "WARN", "Flood wait: " + str(e.seconds) + "s")
            await asyncio.sleep(e.seconds + 60)
            return None
    else:
        try:
            return await client.get_entity(link)
        except Exception as e:
            log(phone, "FAIL", "Link resolve failed: " + str(e)[:50])
            return None


async def get_live_call(client, entity):
    try:
        if getattr(entity, 'megagroup', False) or getattr(entity, 'broadcast', False):
            full = await client(GetFullChannelRequest(entity))
            full_chat = full.full_chat
        else:
            full = await client(GetFullChatRequest(entity.id))
            full_chat = full.full_chat
        call = getattr(full_chat, 'call', None)
        if not call:
            return None
        try:
            info = await client(GetGroupCallRequest(call, limit=0))
            if getattr(info.call, 'schedule_date', None):
                return None
        except Exception:
            pass
        return call
    except errors.FloodWaitError as e:
        await asyncio.sleep(e.seconds + 30)
        return None
    except Exception:
        return None

async def get_joined_channels(client, phone):
    # SIRF CHANNELS (broadcast type) - groups/personal chats skip = fast detection
    found = []
    try:
        async for d in client.iter_dialogs():
            ent = d.entity
            if getattr(ent, 'broadcast', False):
                found.append((ent, getattr(ent, 'title', str(ent.id))))
    except errors.FloodWaitError as e:
        log(phone, "WARN", "Dialogs flood wait: " + str(e.seconds) + "s")
        await asyncio.sleep(e.seconds + 30)
    except Exception as e:
        log(phone, "WARN", "Dialogs fetch failed: " + str(e)[:60])
    log(phone, "OK", str(len(found)) + " channels found (groups/personal skipped)")
    return found

async def get_live_users(client, call, entity, max_users, sent, phone):
    eligible = []
    me_id = (await client.get_me()).id
    active_ids = set()
    all_users = {}

    offset = None
    try:
        while True:
            try:
                if offset:
                    info = await client(GetGroupCallRequest(call, limit=100, offset=offset))
                else:
                    info = await client(GetGroupCallRequest(call, limit=100))
            except TypeError:
                info = await client(GetGroupCallRequest(call, limit=100))
                offset = None
            for p in (info.participants or []):
                uid = getattr(p.peer, 'user_id', None)
                if not uid:
                    continue
                if getattr(p, 'left', False) and not getattr(p, 'date', None):
                    continue
                active_ids.add(uid)
            for u in (info.users or []):
                all_users[u.id] = u
            next_off = getattr(info, 'next_offset', None)
            if not next_off or next_off == offset or len(active_ids) >= 5000:
                break
            offset = next_off
    except errors.FloodWaitError as e:
        log(phone, "WARN", "Flood wait " + str(e.seconds) + "s while fetching live users")
        await asyncio.sleep(e.seconds + 30)
    except Exception as e:
        log(phone, "WARN", "Live users fetch failed: " + str(e)[:60])

    log(phone, "LIVE", str(len(active_ids)) + " participants fetched, " + str(len(all_users)) + " user profiles")

    for uid in active_ids:
        u = all_users.get(uid)
        if u is None:
            continue
        if u.bot or getattr(u, 'deleted', False) or getattr(u, 'scam', False):
            continue
        if uid == me_id or uid in sent:
            continue
        if getattr(u, 'min', False):
            try:
                u = await client.get_entity(uid)
            except Exception:
                continue
        if getattr(u, 'premium', False):
            log(phone, "SKIP", "Premium skipped: " + str(u.first_name))
            continue
        try:
            perms = await client.get_permissions(entity, u)
            if perms.is_admin:
                log(phone, "SKIP", "Admin/Owner skipped: " + str(u.first_name))
                continue
        except Exception:
            pass
        eligible.append(u)
        if max_users and len(eligible) >= max_users:
            break

    return eligible

async def run_live_channel(client, entity, call, name, phone, cfg):
    # Ek live channel ka monitor - multiple lives parallel chaleinge
    a = accounts[phone]
    log(phone, "LIVE", "LIVE DETECTED: " + name)
    a['status'] = "LIVE: " + name
    try:
        while a['running']:
            call = await get_live_call(client, entity)
            if not call:
                break
            users = await get_live_users(client, call, entity, 0, a['sent_users'], phone)
            new = [u for u in users if u.id not in a['sent_users']]
            if new:
                q_now = load_dm_queue(phone)
                space = 100 - len(q_now)
                if space <= 0:
                    log(phone, "DB", "Queue full (100). Waiting for DMs to clear space.")
                else:
                    add_to_queue(phone, [u.id for u in new[:space]])
                    log(phone, "DB", str(min(len(new), space)) + " added (queue: " + str(len(load_dm_queue(phone))) + "/100)")
                if space <= 0:
                    log(phone, "DB", "Queue full (100). Waiting for DMs to clear space.")
                else:
                    add_to_queue(phone, [u.id for u in new[:space]])
                    log(phone, "DB", str(min(len(new), space)) + " added (queue: " + str(len(load_dm_queue(phone))) + "/100)")
                
            await asyncio.sleep(30)
    finally:
        log(phone, "END", "LIVE ENDED: " + name + " - DM queue me bache users peeche se DM honge")
        a['status'] = "Monitoring..."


async def dm_worker(phone, client):
    # Queue se 1-by-1 DM - live khatam ya restart ke baad bhi continue
    a = accounts[phone]
    cfg = a['config']
    queue = load_dm_queue(phone)
    if queue:
        log(phone, "DB", str(len(queue)) + " pending DM(s) queue se load hue")
    while a['running'] or queue:
        if not a.get('dm_on', True):
            await asyncio.sleep(5)
            continue
        # Check force stop first
        if pending.get(phone + "_force"):
            pending.pop(phone + "_force", None)
            log(phone, "WARN", "Force stop! Queue file me saved hai - agle START pe continue hoga.")
            break
        
        # Check if DM is enabled
        if not a.get('dm_on', True):
            await asyncio.sleep(5)
            continue
            
        if not queue:
            queue = load_dm_queue(phone)
            if not queue:
                await asyncio.sleep(10)
                continue
        uid = queue[0]
        if uid in a['sent_users']:
            queue.pop(0)
            remove_from_queue(phone, uid)
            continue
        try:
            await client.get_entity(uid)
        except Exception:
            queue.pop(0)
            remove_from_queue(phone, uid)
            continue
        delay = random.randint(cfg['delay_min'], cfg['delay_max'])
        log(phone, "WAIT", "Waiting " + str(delay) + "s before DM (queue: " + str(len(queue)) + ")")
        await asyncio.sleep(delay)
        try:
            await client.send_message(uid, cfg['message'])
            a['sent_users'].add(uid)
            save_sent_user(phone, uid)
            a['sent_count'] += 1
            log(phone, "SENT", "DM sent to " + str(uid) + " (total: " + str(a['sent_count']) + ")")
        except errors.FloodWaitError as e:
            cool = e.seconds + 60
            log(phone, "WARN", "Flood! " + str(cool) + "s pause, user queue me hai")
            await asyncio.sleep(cool)
            continue
        except errors.PeerFloodError:
            log(phone, "FAIL", "DM daily limit! 6 ghante pause.")
            await asyncio.sleep(21600)
            continue
        except (errors.UserPrivacyRestrictedError, errors.UserIsBlockedError, errors.InputUserDeactivatedError):
            log(phone, "SKIP", "User " + str(uid) + " skip (privacy/blocked/deleted)")
        except Exception as e:
            log(phone, "FAIL", "DM error: " + str(e)[:60])
            await asyncio.sleep(5)
        queue.pop(0)
        remove_from_queue(phone, uid)

async def login_flow(phone, client):
    a = accounts[phone]

    if await client.is_user_authorized():
        me = await client.get_me()
        log(phone, "OK", "Session valid, auto-login: " + str(me.first_name))
        a['status'] = "online"
        return True

    try:
        await client.send_code_request(phone)
    except errors.PhoneNumberInvalidError:
        log(phone, "FAIL", "Invalid phone number!")
        a['status'] = "Failed - invalid phone number"
        return False
    except errors.FloodWaitError as e:
        log(phone, "FAIL", "OTP flood wait: " + str(e.seconds) + "s")
        a['status'] = "Failed - flood wait"
        return False
    except Exception as e:
        log(phone, "FAIL", "OTP send failed: " + str(e)[:60])
        a['status'] = "Failed - OTP could not be sent"
        return False

    a['status'] = "awaiting_otp"
    log(phone, "OTP", "OTP sent to " + phone + " - ENTER IT IN DASHBOARD")

    code = await wait_for_dashboard_value(phone, 'otp', timeout=600)
    if not a['running']:
        return False
    if not code:
        log(phone, "FAIL", "OTP timeout (10 min). Press START again.")
        a['status'] = "Failed - OTP timeout, press START again"
        return False

    try:
        await client.sign_in(phone=phone, code=code)
    except errors.PhoneCodeInvalidError:
        log(phone, "FAIL", "Wrong OTP code!")
        a['status'] = "Failed - wrong OTP, press START again"
        return False
    except errors.PhoneCodeExpiredError:
        log(phone, "FAIL", "OTP expired!")
        a['status'] = "Failed - OTP expired, press START again"
        return False
    except errors.SessionPasswordNeededError:
        a['status'] = "awaiting_2fa"
        log(phone, "OTP", "2FA password required - ENTER IT IN DASHBOARD")
        pwd = await wait_for_dashboard_value(phone, 'twofa', timeout=600)
        if not a['running']:
            return False
        if not pwd:
            log(phone, "FAIL", "2FA timeout. Press START again.")
            a['status'] = "Failed - 2FA timeout, press START again"
            return False
        try:
            await client.sign_in(password=pwd)
        except errors.PasswordHashInvalidError:
            log(phone, "FAIL", "Wrong 2FA password!")
            a['status'] = "Failed - wrong 2FA password"
            return False
    except Exception as e:
        log(phone, "FAIL", "Login failed: " + str(e)[:60])
        a['status'] = "Failed - login error"
        return False

    me = await client.get_me()
    log(phone, "OK", "Logged in successfully: " + str(me.first_name))
    a['status'] = "online"
    if getattr(me, 'username', None):
        a['username'] = me.username
        save_accounts_json()
    return True


async def monitor_loop(phone):
    a = accounts[phone]
    cfg = a['config']
    a['sent_users'] = load_sent_users(phone)
    a['sent_count'] = 0
    log(phone, "OK", "Starting up... " + str(len(a['sent_users'])) + " previously-DMed users loaded")

    client = TelegramClient("session_" + phone, a['api_id'], a['api_hash'])

    try:
        await client.connect()
    except Exception as e:
        log(phone, "FAIL", "Connect failed: " + str(e)[:60])
        a['running'] = False
        a['status'] = "Failed - network error"
        return

    ok = await login_flow(phone, client)
    if not ok:
        await client.disconnect()
        a['running'] = False
        return

    a['status'] = "Monitoring..."

    resolved = []
    if cfg['targets']:
        for link in cfg['targets']:
            try:
                entity = await resolve_target(client, link, phone)
                if entity:
                    resolved.append((entity, getattr(entity, 'title', link)))
            except Exception as e:
                log(phone, "FAIL", "Resolve failed: " + str(e)[:60])
            await asyncio.sleep(5)
    else:
        log(phone, "INFO", "No targets set - auto-detecting joined channels...")
        resolved = await get_joined_channels(client, phone)

    if not resolved:
        log(phone, "FAIL", "No target group could be resolved!")
        a['running'] = False
        a['status'] = "Failed - target not resolved"
        await client.disconnect()
        return

    log(phone, "GO", "Monitoring " + str(len(resolved)) + " group(s) started")

    dm_task = asyncio.create_task(dm_worker(phone, client))

    live_tasks = {}
    while a['running']:
        for entity, name in resolved:
            if not a['running']:
            if not a.get('live_on', True):
                continue
                break
            try:
                call = await get_live_call(client, entity)
                if call and name not in live_tasks:
                    live_tasks[name] = asyncio.create_task(run_live_channel(client, entity, call, name, phone, cfg))
                elif not call and name in live_tasks and live_tasks[name].done():
                    del live_tasks[name]
            except Exception as e:
                log(phone, "WARN", "Error in " + name + ": " + str(e)[:60])
                await asyncio.sleep(5)
        await asyncio.sleep(cfg['check_interval'])

    for t in live_tasks.values():
        t.cancel()
    if load_dm_queue(phone):
        a['status'] = "Finishing queue: " + str(len(load_dm_queue(phone))) + " left (2nd STOP = force)"
        log(phone, "DB", "Stopping after queue drains. " + str(len(load_dm_queue(phone))) + " DM left.")
        await dm_task
        log(phone, "OK", "Queue finished, all DMs sent.")

    await client.disconnect()
    a['status'] = "Stopped"
    log(phone, "BYE", "Client disconnected.")

def run_account_thread(phone):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(monitor_loop(phone))
    except Exception as e:
        log(phone, "FAIL", "Bot crashed: " + str(e)[:80])
        a = accounts.get(phone)
        if a:
            a['running'] = False
            a['status'] = "Error - crash"


def start_account(phone):  # FIXED: Added missing colon
    a = accounts.get(phone)
    if not a:
        return "Account not found!"
    if not can_touch(a.get('owner', 'admin')):
        return "This account does not belong to you!"
    if a['running']:
        return "This account is already running!"
    cfg = a['config']
    if not cfg['message']:
        return "Save this account's config first (message required)! Targets optional - auto-detect will be used."
    make_pending(phone)
    a['live_on'] = True
    a['dm_on'] = True
    a['running'] = True
    a['status'] = "Starting... sending OTP"
    t = threading.Thread(target=run_account_thread, args=(phone,), daemon=True)
    a['thread'] = t
    t.start()
    return phone + " started! OTP will arrive on that number's Telegram - enter it in your tab."


def stop_account(phone):
    a = accounts.get(phone)
    if not a:
        return "Account not found!"
    if not can_touch(a.get('owner', 'admin')):
        return "This account is not yours!"
    a['running'] = False
    if a['status'].startswith('Finishing'):
        a['status'] = "Force stop..."
        pending[phone + "_force"] = True
    a['status'] = "Stopping..."
    unblock_pending(phone)
    return phone + " stop signal sent"


# ---------------- AUTH / ROUTES ----------------

@app.before_request
def require_login():
    if request.path in ('/login', '/logout') or request.path.startswith('/api/forgot'):
        return None
    uname = session.get('username')
    u = get_user(uname) if uname else None
    if not u or not u.get('active', True):
        session.clear()
        return send_from_directory('.', 'login.html')
    va = session.get('view_as')
    if va:
        vu = get_user(va)
        if not vu or not vu.get('active', True):
            session.pop('view_as', None)
    if request.path == '/admin' or request.path.startswith('/api/admin'):
        if u.get('role') != 'admin':
            return send_from_directory('.', 'login.html')
    return None


@app.route('/login', methods=['POST'])
def api_login():
    data = request.json or {}
    uname = (data.get('username') or '').strip()
    pwd = data.get('password') or ''
    now = datetime.now().timestamp()
    att = login_attempts.get(uname, {'count': 0, 'until': 0})
    if att['until'] > now:
        wait = int(att['until'] - now)
        return jsonify({'msg': 'Too many failed attempts! Try again in ' + str(wait) + ' seconds.'}), 429
    u = get_user(uname)
    if not u or not verify_val(u['password'], pwd):
        att['count'] = att.get('count', 0) + 1
        if att['count'] >= MAX_ATTEMPTS:
            att['count'] = 0
            att['until'] = now + LOCK_SECONDS
        login_attempts[uname] = att
        return jsonify({'msg': 'Wrong username or password!'}), 401
    login_attempts.pop(uname, None)
    if not u.get('active', True):
        return jsonify({'msg': 'This account has been disabled by admin!'}), 401
    session['username'] = uname
    session['role'] = u.get('role', 'user')
    session.permanent = True
    return jsonify({'msg': 'ok', 'role': session['role']})


@app.route('/logout')
def logout():
    session.clear()
    return send_from_directory('.', 'login.html')


@app.route('/whoami')
def api_whoami():
    return jsonify({'view_as': session.get('view_as', ''), 'role': session.get('role', 'user')})


@app.route('/')
def home():
    return send_from_directory('.', 'dashboard.html')


@app.route('/admin')
def admin_page():
    return send_from_directory('.', 'admin.html')


@app.route('/api/accounts')
def api_accounts():
    eff = effective_user()
    show_all = is_admin_session() and not session.get('view_as')
    with state_lock:
        data = []
        total_sent = 0
        for phone, a in accounts.items():
            if not show_all and a.get('owner', 'admin') != eff:
                continue
            total_sent += a['sent_count']
            data.append({
                'label': a['label'], 'phone': phone,
                'username': a.get('username', ''),
                'status': a['status'],
                'state': status_state(a),
                'queue_count': len(load_dm_queue(phone)),
                'live_on': a.get('live_on', True),
                'dm_on': a.get('dm_on', True),  # FIXED: Added missing comma
                'sent_count': a['sent_count'],
                'live_on': a.get('live_on', True),
                'dm_on': a.get('dm_on', True)
            })
        return jsonify({'accounts': data, 'total_sent': total_sent})


@app.route('/api/logs')
def api_logs():
    phone = request.args.get('phone', '')
    with state_lock:
        a = accounts.get(phone)
        if a and not can_touch(a.get('owner', 'admin')):
            return jsonify({'logs': []})
        return jsonify({'logs': logs.get(phone, [])[-100:]})


@app.route('/api/account/config', methods=['GET', 'POST'])
def api_account_config():
    phone = request.args.get('phone') if request.method == 'GET' else request.json.get('phone')
    with state_lock:
        a = accounts.get(phone)
        if not a:
            return jsonify({'msg': 'Account not found!'} if request.method == 'POST' else {})
        if not can_touch(a.get('owner', 'admin')):
            return jsonify({'msg': 'This account is not yours!'} if request.method == 'POST' else {})
        if request.method == 'GET':
            return jsonify(a['config'])
        data = request.json
        owner = a.get('owner', 'admin')
        _, max_targets = user_limits(owner)
        targets = data.get('targets', [])
        if len(targets) > max_targets:
            return jsonify({'msg': 'LIMIT REACHED! This user is allowed maximum ' + str(max_targets) + ' target groups (you entered ' + str(len(targets)) + ')'})
        a['config'] = {
            'channel_link': data.get('channel_link', ''),
            'targets': targets,
            'message': data.get('message', ''),
            'max_users': data.get('max_users', 8),
            'check_interval': data.get('check_interval', 45),
            'delay_min': data.get('delay_min', 40),
            'delay_max': data.get('delay_max', 75)
        }
        save_accounts_json()
        return jsonify({'msg': a['label'] + ' config saved successfully!'})


@app.route('/api/account/add', methods=['POST'])
def api_account_add():
    data = request.json
    phone = (data.get('phone') or '').strip()
    if not phone.startswith('+'):
        return jsonify({'msg': 'Enter phone in +91XXXXXXXXXX format!'})
    eff = effective_user()
    if not eff:
        return jsonify({'msg': 'Login first!'})
    max_acc, _ = user_limits(eff)
    with state_lock:
        if phone in accounts:
            return jsonify({'msg': 'This account is already added!'})
        owned = sum(1 for acc in accounts.values() if acc.get('owner', 'admin') == eff)
        if owned >= max_acc:
            return jsonify({'msg': 'LIMIT REACHED! You can add maximum ' + str(max_acc) + ' Telegram accounts. Ask admin to increase your limit.'})
        accounts[phone] = {
            'label': data.get('label') or phone,
            'phone': phone,
            'api_id': int(data['api_id']),
            'api_hash': (data.get('api_hash') or '').strip(),
            'username': data.get('username', ''),
            'owner': eff,
            'running': False,
            'thread': None,
            'sent_users': set(),
            'sent_count': 0,
            'status': 'Ready',
            'config': default_config()
        }
        save_accounts_json()
    return jsonify({'msg': phone + ' added! Now open its tab and fill the config.'})


@app.route('/api/account/remove', methods=['POST'])
def api_account_remove():
    phone = request.json.get('phone')
    with state_lock:
        a = accounts.get(phone)
        if not a:
            return jsonify({'msg': 'Account not found!'})
        if not can_touch(a.get('owner', 'admin')):
            return jsonify({'msg': 'This account is not yours!'})
        if a['running']:
            return jsonify({'msg': 'STOP it first, then delete!'})
        del accounts[phone]
        pending.pop(phone, None)
        save_accounts_json()
    return jsonify({'msg': phone + ' deleted'})


@app.route('/api/account/start', methods=['POST'])
def api_account_start():
    msg = start_account(request.json.get('phone'))
    return jsonify({'msg': msg})


@app.route('/api/account/stop', methods=['POST'])
def api_account_stop():
    msg = stop_account(request.json.get('phone'))
    return jsonify({'msg': msg})


@app.route('/api/account/verify-otp', methods=['POST'])
def api_verify_otp():
    phone = request.json.get('phone')
    code = (request.json.get('code') or '').strip()
    a = accounts.get(phone)
    if a and not can_touch(a.get('owner', 'admin')):
        return jsonify({'msg': 'This account is not yours!'})
    p = pending.get(phone)
    if not p or p['waiting'] != 'otp':
        return jsonify({'msg': 'No OTP was requested for this account! Press START first.'})
    if not code:
        return jsonify({'msg': 'OTP box is empty!'})
    p['otp_value'] = code
    p['otp_event'].set()
    return jsonify({'msg': 'OTP received, verifying...'})


@app.route('/api/account/verify-2fa', methods=['POST'])
def api_verify_2fa():
    phone = request.json.get('phone')
    password = request.json.get('password') or ''
    a = accounts.get(phone)
    if a and not can_touch(a.get('owner', 'admin')):
        return jsonify({'msg': 'This account is not yours!'})
    p = pending.get(phone)
    if not p or p['waiting'] != 'twofa':
        return jsonify({'msg': 'This account does not need 2FA right now!'})
    if not password:
        return jsonify({'msg': '2FA password is empty!'})
    p['twofa_value'] = password
    p['twofa_event'].set()
    return jsonify({'msg': '2FA password received, verifying...'})


@app.route('/api/stop-all', methods=['POST'])
def api_stop_all():
    for phone in list(accounts.keys()):
        a = accounts.get(phone)
        if a and can_touch(a.get('owner', 'admin')):
            stop_account(phone)
    return jsonify({'msg': 'Stop signal sent to all your accounts'})

@app.route('/api/account/toggle-live', methods=['POST'])
def api_toggle_live():
    phone = request.json.get('phone')
    with state_lock:
        a = accounts.get(phone)
        if not a:
            return jsonify({'msg': 'Account not found!'})
        if not can_touch(a.get('owner', 'admin')):
            return jsonify({'msg': 'This account is not yours!'})
        if not a['running']:
            return jsonify({'msg': 'START first, then toggle!'})
        a['live_on'] = not a.get('live_on', True)
        msg = "Live monitoring ON - live detect + queue add active"
        if not a['live_on']:
            msg = "Live monitoring OFF - live detect + queue add paused (DM queue continues)"
        log(phone, "INFO", msg)
        return jsonify({'msg': msg, 'live_on': a['live_on']})


@app.route('/api/account/toggle-dm', methods=['POST'])
def api_toggle_dm():
    phone = request.json.get('phone')
    with state_lock:
        a = accounts.get(phone)
        if not a:
            return jsonify({'msg': 'Account not found!'})
        if not can_touch(a.get('owner', 'admin')):
            return jsonify({'msg': 'This account is not yours!'})
        if not a['running']:
            return jsonify({'msg': 'START first, then toggle!'})
        a['dm_on'] = not a.get('dm_on', True)
        msg = "DM ON - queue DM active"
        if not a['dm_on']:
            msg = "DM OFF - DM paused, live detect + queue add continues"
        log(phone, "INFO", msg)
        return jsonify({'msg': msg, 'dm_on': a['dm_on']})

# ---------------- FORGOT PASSWORD (SECURITY QUESTION) ----------------

@app.route('/api/forgot/question')
def api_forgot_question():
    uname = (request.args.get('username') or '').strip()
    u = get_user(uname)
    if not u:
        return jsonify({'msg': 'This username does not exist!'}), 404
    if not u.get('security_question'):
        return jsonify({'msg': 'No security question set for this user! Ask admin to reset your password.'}), 404
    return jsonify({'question': u['security_question']})


@app.route('/api/forgot/reset', methods=['POST'])
def api_forgot_reset():
    data = request.json or {}
    uname = (data.get('username') or '').strip()
    ans = (data.get('answer') or '').strip().lower()
    new = (data.get('new_password') or '').strip()
    u = get_user(uname)
    if not u:
        return jsonify({'msg': 'This username does not exist!'}), 404
    if not u.get('security_answer'):
        return jsonify({'msg': 'No security question set for this user! Ask admin to reset.'}), 404
    if not verify_val(u['security_answer'], ans):
        return jsonify({'msg': 'Wrong answer! Try again.'}), 401
    if len(new) < 6:
        return jsonify({'msg': 'New password must be at least 6 characters!'})
    u['password'] = hash_val(new)
    save_users()
    return jsonify({'msg': 'Password reset successful! Now login with your new password.'})


# ---------------- ADMIN PANEL APIs ----------------

@app.route('/api/admin/users')
def api_admin_users():
    with state_lock:
        data = []
        for u in users_list:
            accs = [a for a in accounts.values() if a.get('owner', 'admin') == u['username']]
            data.append({
                'username': u['username'],
                'role': u.get('role', 'user'),
                'active': u.get('active', True),
                'max_accounts': u.get('max_accounts', 5),
                'max_targets': u.get('max_targets', 3),
                'has_sq': bool(u.get('security_question') and u.get('security_answer')),
                'accounts_count': len(accs),
                'running_count': sum(1 for a in accs if a['running'])
            })
        return jsonify({'users': data, 'view_as': session.get('view_as', '')})


@app.route('/api/admin/user/create', methods=['POST'])
def api_admin_user_create():
    data = request.json or {}
    uname = (data.get('username') or '').strip().lower()
    pwd = (data.get('password') or '').strip()
    sq = (data.get('security_question') or '').strip()
    sa = (data.get('security_answer') or '').strip().lower()
    if not uname or not pwd:
        return jsonify({'msg': 'Username and password are both required!'})
    if ' ' in uname:
        return jsonify({'msg': 'Username cannot contain spaces!'})
    if not sq or not sa:
        return jsonify({'msg': 'Security Question and Answer are required (for forgot password)!'})
    try:
        max_acc = max(0, int(data.get('max_accounts', 5)))
        max_tar = max(0, int(data.get('max_targets', 3)))
    except Exception:
        max_acc, max_tar = 5, 3
    with state_lock:
        if get_user(uname):
            return jsonify({'msg': 'This username already exists!'})
        users_list.append({
            'username': uname, 'password': hash_val(pwd), 'role': 'user',
            'active': True, 'max_accounts': max_acc, 'max_targets': max_tar,
            'security_question': sq, 'security_answer': hash_val(sa)
        })
        save_users()
    return jsonify({'msg': 'User "' + uname + '" created! Login: ' + uname + ' / ' + pwd})


@app.route('/api/admin/user/update', methods=['POST'])
def api_admin_user_update():
    data = request.json or {}
    uname = data.get('username')
    with state_lock:
        u = get_user(uname)
        if not u:
            return jsonify({'msg': 'User not found!'})
        if 'active' in data:
            if uname == 'admin':
                return jsonify({'msg': 'Admin cannot be disabled!'})
            u['active'] = bool(data['active'])
        new_pwd = (data.get('password') or '').strip()
        if new_pwd:
            u['password'] = hash_val(new_pwd)
        for k in ('max_accounts', 'max_targets'):
            if k in data:
                try:
                    u[k] = max(0, int(data[k]))
                except Exception:
                    pass
        new_q = (data.get('security_question') or '').strip()
        if new_q:
            u['security_question'] = new_q
        new_a = (data.get('security_answer') or '').strip().lower()
        if new_a:
            u['security_answer'] = hash_val(new_a)
        save_users()
    return jsonify({'msg': uname + ' updated successfully!'})


@app.route('/api/admin/user/delete', methods=['POST'])
def api_admin_user_delete():
    uname = (request.json or {}).get('username')
    if uname == 'admin':
        return jsonify({'msg': 'Admin cannot be deleted!'})
    with state_lock:
        u = get_user(uname)
        if not u:
            return jsonify({'msg': 'User not found!'})
        running = [p for p, a in accounts.items() if a.get('owner', 'admin') == uname and a['running']]
        if running:
            return jsonify({'msg': 'First STOP this user\'s ' + str(len(running)) + ' running account(s), then delete!'})
        for p in [p for p, a in accounts.items() if a.get('owner', 'admin') == uname]:
            del accounts[p]
            pending.pop(p, None)
        users_list[:] = [x for x in users_list if x['username'] != uname]
        save_accounts_json()
        save_users()
    return jsonify({'msg': 'User "' + uname + '" and all their accounts deleted'})


@app.route('/api/admin/change-password', methods=['POST'])
def api_admin_change_password():
    data = request.json or {}
    me = get_user(session.get('username', ''))
    if not me:
        return jsonify({'msg': 'Session error, please login again!'}), 401
    if not verify_val(me['password'], data.get('old_password') or ''):
        return jsonify({'msg': 'Old password is wrong!'}), 401
    new = (data.get('new_password') or '').strip()
    if len(new) < 6:
        return jsonify({'msg': 'New password must be at least 6 characters!'})
    me['password'] = hash_val(new)
    save_users()
    return jsonify({'msg': 'Password changed successfully! Remember your new password.'})


@app.route('/api/admin/view-as', methods=['POST'])
def api_admin_view_as():
    data = request.json or {}
    uname = (data.get('username') or '').strip()
    if not uname:
        session.pop('view_as', None)
        return jsonify({'msg': 'Back to admin view'})
    u = get_user(uname)
    if not u:
        return jsonify({'msg': 'User not found!'})
    if uname != session.get('username') and not u.get('active', True):
        return jsonify({'msg': 'User is disabled, activate them first!'})
    session['view_as'] = uname
    return jsonify({'msg': 'Now opening "' + uname + '" dashboard...'})


def restore_accounts():
    for acc in load_accounts_json():
        phone = acc['phone']
        cfg = default_config()
        cfg.update(acc.get('config', {}))
        accounts[phone] = {
            'label': acc['label'], 'phone': phone,
            'api_id': acc['api_id'], 'api_hash': acc['api_hash'],
            'username': acc.get('username', ''),
            'owner': acc.get('owner', 'admin'),
            'running': False, 'thread': None,
            'live_on': True, 'dm_on': True,
            'sent_users': set(), 'sent_count': 0, 'status': 'Ready',
            'config': cfg
        }
    if accounts:
        print(str(len(accounts)) + " telegram account(s) loaded from file")


@app.route('/back-to-admin')
def back_to_admin():
    from flask import redirect
    session.pop('view_as', None)
    return redirect('/admin')

if __name__ == '__main__':
    init_users()
    restore_accounts()
    print("Dashboard: http://0.0.0.0:5000")
    print("Admin Panel: http://0.0.0.0:5000/admin")
    app.run(host='0.0.0.0', port=5000)
