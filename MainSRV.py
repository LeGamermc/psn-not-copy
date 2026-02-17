from flask import Flask, Response, request
import sqlite3
import hashlib
import secrets
import time
import threading
import os
import random

#NOTICE:
#important stuff you will need before working:
#https://www.psdevwiki.com/ps3/Error_Codes
#https://www.psdevwiki.com/ps3/PSN - maybe outdated

#The current state of the project is active, you will need firmware version 4.88 from evilnat or any CFW provider and my instruction to setup the local server properly
#known problems ive incountered:
# when login in using a valid PSID (fake or not), get PSN error 8002AA03 - Invalid Argument (observation: only happen at the account id [not after not before])
# when login in using bad PSID (not matching Xregistry.sys), get PSN error Cannot sign in using a other loginid (email address) [missmatched Xregistry psid to given psid]

#known stuff
#ticket formation is valid, i tried to mess with the ticket stuff and we got on invalid formated ticket psn error 8002AB04 - Parser error (SCE_NP_UTIL_ERROR_PARSER_FAILED)

#!!IMPORTANT!!
#why 4.88 and not 4.92?
#because on the 4.92 version they changed how the token was created and so when a 4.88 fw connect on the modern backend it thinks its invalid and give the psn error 80710016 - That header does not exist 
#what do i want?
#someone that will at least give me a valid token responce for 4.92 or give me responce endpoint for the differant part [/auth/nav, profile, register endpoint [emailverif.xml], commerce endpoint], by using the ssl breaking stuff i cannot seem to do

debug = 1
app = Flask(__name__)

KNOWN_PSIDS = {
    "test@t.co": "0200000000000000" #YOUR XREGISTRY MUST HAVE THIS!!! (else you will get a Cannot sign in using a other loginid error!)
}

KNOWN_USERNAMES = {
    "test@t.co": "eeee"  # some random ass username
}

KNOWN_COUNTRIES = {
    "test@t.co": "US"  # country
}


def ticket_gen(loginid, password, serviceid):
    if not loginid or not password or not serviceid:
        return None

    seed_string = loginid + password
    seed_value = int(hashlib.sha256(seed_string.encode()).hexdigest(), 16) % (2**32)
    rng = random.Random(seed_value)

    def rand_bytes(length):
        return ''.join(format(rng.randint(0, 255), '02x') for _ in range(length))

    def padstr(s, total_bytes):
        h = s.encode('utf-8').hex()
        total = total_bytes * 2
        return (h + '0' * total)[:total]

    def padnum(n, chars):
        return format(n, 'x').zfill(chars)

    serial_id   = rand_bytes(20)      
    issuer_id   = "00000100"     

    now_ms      = int(time.time() * 1000)
    start_ts    = padnum(now_ms, 16)
    end_ts      = padnum(now_ms + 86400000, 16) 

    if loginid in KNOWN_PSIDS:
        account_id = KNOWN_PSIDS[loginid]
    else:
        account_id = hashlib.sha256((loginid + "ACCOUNT").encode()).hexdigest()[:16]

    if loginid in KNOWN_USERNAMES:
        username = KNOWN_USERNAMES[loginid]
    else:
        username = loginid.split("@")[0] if "@" in loginid else loginid

    username_padded = padstr(username, 32)

    if loginid in KNOWN_COUNTRIES and KNOWN_COUNTRIES[loginid] == "FR":
        lang = "66720002"
    else:
        lang = "75730001"

    unknown_0x80 = "00000000"

    service_id_padded = padstr(serviceid, 24)

    year_of_birth  = format(rng.randint(1970, 2006), '04x')
    month_of_birth = format(rng.randint(1, 12), '02x')
    day_of_birth   = format(rng.randint(1, 28), '02x')
    dob_field = "07" + year_of_birth + month_of_birth + day_of_birth

    dob_field = "07" + format(rng.randint(1970, 2006) % 256, '02x') + month_of_birth + day_of_birth #i shit you not ill do a better job when we will have a db
    unknown_0xac = "00000200"

    footer_net   = rand_bytes(4) 
    footer_sig   = rand_bytes(20)

    # ── Build body (from 0x0c to 0xb7 = 0xac bytes) ──────────────────────
    body  = f"00080014{serial_id}"          # 0x0c limiter + 0x10 data
    body += f"00010004{issuer_id}"          # 0x24 limiter + 0x28 data
    body += f"00070008{start_ts}"           # 0x2c limiter + 0x30 data
    body += f"00070008{end_ts}"             # 0x38 limiter + 0x3c data
    body += f"00020008{account_id}"         # 0x44 limiter + 0x48 data <- seemingly there that break [like we get past that but anything below it is ignored]
    body += f"00040020{username_padded}"    # 0x50 limiter + 0x54 data
    body += f"00080004{lang}"              # 0x74 limiter + 0x78 data
    body += f"00040004{unknown_0x80}"      # 0x7c limiter + 0x80 data
    body += f"00080018{service_id_padded}" # 0x84 limiter + 0x88 data
    body += f"30110004{dob_field}"         # 0xa0 limiter + 0xa4 data
    body += f"00010004{unknown_0xac}"      # 0xa8 limiter + 0xac data
    body += "3010000000000000"             # 0xb0: fixed 8 bytes

    body_bytes = len(body) // 2
    assert body_bytes == 0xac, f"Body is {body_bytes} bytes, expected {0xac}"

    # ── Build footer (from 0xbc to 0xdb = 0x20 bytes) ────────────────────
    footer  = f"00080004{footer_net}"   # 0xbc limiter + 0xc0 data (4 bytes)
    footer += f"00080014{footer_sig}"   # 0xc4 limiter + 0xc8 data (20 bytes)

    footer_bytes = len(footer) // 2
    assert footer_bytes == 0x20, f"Footer is {footer_bytes} bytes, expected {0x20}"

    # ── Assemble ──────────────────────────────────────────────────────────
    frames  = f"300000ac{body}"
    frames += f"30020020{footer}"

    total_size = len(frames) // 2
    assert total_size == 0xd4, f"Total size is {total_size}, expected {0xd4}"

    ticket_hex = f"31000000{padnum(total_size, 8)}{frames}"

    return bytes.fromhex(ticket_hex)

if debug == 1:
    @app.before_request
    def log_request():
        print(f"\n{'='*60}")
        print(f"[REQUEST] {request.method} {request.path}")
        print(f"[FROM] {request.remote_addr}")
        print(f"[HEADERS] {dict(request.headers)}")
        if request.form:
            print(f"[FORM] {dict(request.form)}")
        if request.args:
            print(f"[ARGS] {dict(request.args)}")
        print(f"{'='*60}\n")

    @app.after_request
    def log_response(response):
        print(f"\n[RESPONSE] Status: {response.status_code}")
        print(f"[RESPONSE] Headers: {dict(response.headers)}")
        if response.data and len(response.data) < 500:
            print(f"[RESPONSE] Body (hex): {response.data.hex()[:200]}")
            print(f"[RESPONSE] Body (text): {response.data.decode('utf-8', errors='ignore')[:500]}")
        print(f"{'-'*60}\n")
        return response

#for now useless asf
#def init_db():
#    conn = sqlite3.connect('psn.db')
#    c = conn.cursor()
#    
#    c.execute('''CREATE TABLE IF NOT EXISTS users
#                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, 
#                  email TEXT, psid TEXT, jid TEXT, aboutme TEXT, avatarurl TEXT,
#                  plus_status INTEGER, created_at INTEGER)''')
#    
#    c.execute('''CREATE TABLE IF NOT EXISTS profiles
#                 (username TEXT PRIMARY KEY, online_id TEXT, aboutme TEXT,
#                  avatarurl TEXT, plus_icon INTEGER, country TEXT)''')
#    
#    c.execute('''CREATE TABLE IF NOT EXISTS products
#                 (product_id TEXT PRIMARY KEY, title TEXT, description TEXT,
#                  price REAL, category TEXT, content_id TEXT, platform TEXT)''')
#    
#    c.execute('''CREATE TABLE IF NOT EXISTS licenses
#                 (username TEXT, product_id TEXT, console_id TEXT,
#                  activation_date INTEGER, rif_data TEXT,
#                  PRIMARY KEY (username, product_id))''')
#    
#    c.execute('''CREATE TABLE IF NOT EXISTS drm_activations
#                 (username TEXT PRIMARY KEY, console_id TEXT, act_dat TEXT,
#                  max_consoles INTEGER, current_consoles INTEGER)''')
#    
#    conn.commit()
#    conn.close()

#def create_user(username, password, email):
#    conn = sqlite3.connect('psn.db')
#    c = conn.cursor()
#    
#    psid = secrets.token_hex(8)
#    jid = f"{username}@communication.playstation.net"
#    password_hash = hashlib.sha256(password.encode()).hexdigest()
#    
#    try:
#        c.execute('''INSERT INTO users (username, password, email, psid, jid, aboutme, avatarurl, plus_status, created_at)
#                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
#                  (username, password_hash, email, psid, jid, "", "", 0, int(time.time())))
#        
#        c.execute('''INSERT INTO profiles (username, online_id, aboutme, avatarurl, plus_icon, country)
#                     VALUES (?, ?, ?, ?, ?, ?)''',
#                  (username, username, "PS3 User", "http://kns-srv2.zapto.org:82/psn/DefaultAvatar.png", 0, "US"))
#        
#        c.execute('''INSERT INTO drm_activations (username, console_id, act_dat, max_consoles, current_consoles)
#                     VALUES (?, ?, ?, ?, ?)''',
#                  (username, "", "", 2, 0))
#        
#        conn.commit()
#    except sqlite3.IntegrityError:
#        print(f"User {username} already exists")
#    finally:
#        print(f"Created user: {username}")
#        conn.close()
#    return psid, jid

# ─── Networking ────────────────────────────────────────────────────────────
#not used before /auth/nav
@app.route('/networktest/get_2m', methods=['GET'])
def get_2m():
    data = b'\x00' * (2 * 1024 * 1024)
    return Response(data, status=200, mimetype='application/octet-stream')

@app.route('/networktest/post_128', methods=['POST'])
def post_128():
    return '<HTML>Request Processed\n</HTML>', 200

@app.route('/networktest/post', methods=['POST'])
def post_generic():
    return '<HTML>Request Processed\n</HTML>', 200

#this is ena.playstation.net (on vsh.elf you will need to manualy put your domain:80 if you want access to internet features)
@app.route('/netstart/ps3', methods=['GET'])
def netstart():
    return Response('3', mimetype='text/plain', headers={
        'ETag': '"eccbc87e4b5ce2fe28308fd9f2a7baf3:1525658254"',
        'Last-Modified': 'Tue, 07 Jun 2011 00:00:00 GMT',
    })

# to get what's new working 
@app.route('/kamaji/api/swordfish/<path:subpath>', methods=['GET', 'POST'])
def kamaji(subpath):
    return Response('<?xml version="1.0"?><notifications><list></list></notifications>', mimetype='text/xml')

# ─── Auth ────────────────────────────────────────────────────────────────────
#look on the known issue before thinking shit works thanks (taken but modified from hyena [for context hyena version didnt even got past the Xregistry stuff it had a invalid header on the token responce])
#no password check cuz yes
@app.route('/nav/auth', methods=['POST'])
def auth():
    data = request.form
    loginid = data.get('loginid') or data.get('username')
    password = data.get('password')
    serviceid = data.get('serviceid')
 
    if not loginid or not password or not serviceid:
        return Response('reason=AUTH_FAILED', status=401)

    print(f"  Service ID: {serviceid}")

    ticket_binary = ticket_gen(loginid, password, serviceid)
    
    if not ticket_binary:
        print("[AUTH] ERROR: Failed to generate ticket")
        return Response('reason=TICKET_GEN_FAILED', status=500)
    
    response = Response(ticket_binary, status=200)
    response.headers['Content-Type'] = 'application/x-i-5-ticket'
    response.headers['X-I-5-Version'] = '4.0'
    response.headers['X-N'] = 'S'
    response.headers['X-I-5-Status'] = 'OK'
    return response

# ─── Profiles ────────────────────────────────────────────────────────────────
#i dont even know if this works 
@app.route('/basic_view/sec/get_self_profile', methods=['POST'])
def get_self_profile():
    data = request.form
    ticket_b64 = data.get('ticket')
    env = data.get('env', 'np')
    
    if not ticket_b64:
        print("[PROFILE] No ticket in form data")
        return Response('NO_TICKET', status=401)
    
    try:
        import base64
        try:
            ticket_bytes = base64.b64decode(ticket_b64)
        except:
            ticket_bytes = bytes.fromhex(ticket_b64)
        
        ticket_hex = ticket_bytes.hex()
        
        # Extract username from ticket at offset 0x50
        username_offset = 0x50 * 2
        username_section_start = username_offset + 8
        
        username_hex = ""
        for i in range(username_section_start, username_section_start + 64, 2):
            byte_hex = ticket_hex[i:i+2]
            if byte_hex == "00":
                break
            username_hex += byte_hex
        
        online_id = bytes.fromhex(username_hex).decode('utf-8')
        print(f"[PROFILE] Extracted username: {online_id}")
        
    except Exception as e:
        print(f"[PROFILE] Error reading ticket: {e}")
        return Response('INVALID_TICKET', status=400)
    
    domain_offset = 0x7C * 2
    domain_hex = ticket_hex[domain_offset + 8:domain_offset + 16]
    
    jid = f"{online_id}@{bytes.fromhex(domain_hex[:6]).decode('utf-8', errors='ignore')}.{env}"
    
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<profile result="00">
  <jid>{jid}</jid>
  <onlinename upd="0">{online_id}</onlinename>
  <country>US</country>
  <language1>1</language1>
  <language2></language2>
  <language3></language3>
  <aboutme>Description About Me</aboutme>
  <avatarurl id="1000">http://kns-srv2.zapto.org:82/psn/DefaultAvatar.png</avatarurl>
  <ptlp>0F0E0E00</ptlp>
</profile>'''
    
    return Response(xml, mimetype='text/xml')

@app.route('/basic_view/func/get_profile', methods=['GET', 'POST'])
def get_profile():
    searchjid = request.args.get('searchjid') or request.form.get('searchjid')
    username = searchjid.split('@')[0] if searchjid else None

    conn = sqlite3.connect('psn.db')
    c = conn.cursor()
    c.execute('SELECT online_id, aboutme, avatarurl, plus_icon, country FROM profiles WHERE username=?', (username,))
    profile = c.fetchone()
    conn.close()

    if not profile:
        return Response('PROFILE_NOT_FOUND', status=404)

    online_id, aboutme, avatarurl, plus_icon, country = profile
    jid = f"{online_id}@communication.playstation.net"

    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<profile>
  <jid>{jid}</jid>
  <online-id>{online_id}</online-id>
  <aboutme>{aboutme}</aboutme>
  <avatarurl>{avatarurl}</avatarurl>
  <plus-icon>{plus_icon}</plus-icon>
  <country>{country}</country>
</profile>'''

    return Response(xml, mimetype='text/xml')

# ─── Commerce / DRM ──────────────────────────────────────────────────────────
#same thing i dont know if this work i never could go past /auth/nav
@app.route('/cap.m', methods=['POST'])
def commerce_activate():
    data = request.form
    loginid = data.get('loginid')
    password = data.get('password')
    consoleid = data.get('consoleid')
    productid = data.get('productid')

    conn = sqlite3.connect('psn.db')
    c = conn.cursor()

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    c.execute('SELECT username FROM users WHERE username=? AND password=?', (loginid, password_hash))
    result = c.fetchone()

    if not result:
        conn.close()
        return Response('reason=AUTH_FAILED', status=401, mimetype='application/x-i-5-drm')

    username = result[0]

    c.execute('SELECT max_consoles, current_consoles FROM drm_activations WHERE username=?', (username,))
    drm = c.fetchone()

    if drm and drm[1] >= drm[0]:
        conn.close()
        return Response(f'reason=max_console={drm[0]}&current_console={drm[1]}',
                        status=403, mimetype='application/x-i-5-drm')

    rif_data = secrets.token_hex(128)

    c.execute('''INSERT OR REPLACE INTO licenses (username, product_id, console_id, activation_date, rif_data)
                 VALUES (?, ?, ?, ?, ?)''',
              (username, productid, consoleid, int(time.time()), rif_data))

    c.execute('UPDATE drm_activations SET current_consoles = current_consoles + 1, console_id = ? WHERE username = ?',
              (consoleid, username))

    conn.commit()
    conn.close()

    return Response(f'reason=OK\n{rif_data}', mimetype='application/x-i-5-drm')

@app.route('/cdp.m', methods=['POST'])
def commerce_deactivate():
    data = request.form
    loginid = data.get('loginid')
    password = data.get('password')
    consoleid = data.get('consoleid')
    productid = data.get('productid')

    conn = sqlite3.connect('psn.db')
    c = conn.cursor()

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    c.execute('SELECT username FROM users WHERE username=? AND password=?', (loginid, password_hash))
    result = c.fetchone()

    if not result:
        conn.close()
        return Response('reason=AUTH_FAILED', status=401, mimetype='application/x-i-5-drm')

    username = result[0]

    c.execute('DELETE FROM licenses WHERE username=? AND product_id=? AND console_id=?',
              (username, productid, consoleid))

    c.execute('UPDATE drm_activations SET current_consoles = MAX(0, current_consoles - 1) WHERE username = ?',
              (username,))

    conn.commit()
    conn.close()

    return Response('reason=OK', mimetype='application/x-i-5-drm')

@app.route('/kdp.m', methods=['POST'])
def commerce_keydata():
    data = request.form
    loginid = data.get('loginid')
    password = data.get('password')
    productid = data.get('productid')

    conn = sqlite3.connect('psn.db')
    c = conn.cursor()

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    c.execute('SELECT username FROM users WHERE username=? AND password=?', (loginid, password_hash))
    result = c.fetchone()

    if not result:
        conn.close()
        return Response('reason=AUTH_FAILED', status=401, mimetype='application/x-i-5-drm')

    username = result[0]

    c.execute('SELECT rif_data FROM licenses WHERE username=? AND product_id=?', (username, productid))
    license = c.fetchone()
    conn.close()

    if not license:
        return Response('reason=NOT_FOUND', status=404, mimetype='application/x-i-5-drm')

    return Response(f'reason=OK\n{license[0]}', mimetype='application/x-i-5-drm')

# ─── Registration ─────────────────────────────────────────────────────────────
#ONLY REG GET COUNTRY, REGTOP, PSN (just need to copy some of the .dat file from the hyena project) IS VERIFIED WORKING!!
@app.route('/native/reg/getCountries.action', methods=['GET'])
def get_countries():
    with open('countries.bin', 'rb') as f:
        data = f.read()
    return Response(data, mimetype='text/plain', headers={
        'X-NativeBuildVersion': '20.00.00.00',
        'X-NativeResult': '0',
    })

@app.route('/native/reg/bindAccount.action', methods=['POST'])
def auth_bind():
    return Response('Not found', status=404)

@app.route('/nsx/sec/Xz78TMQ1Uf31VCYr/c/NSXVID/NSXVID-PN.P3.0085-REGTOP.xml', methods=['GET', 'POST'])
def get_regtop():
    with open('REGTOP.xml', 'rb') as f:
        data = f.read()
    return Response(data, mimetype='text/xml')  # data not xml

@app.route('/ps3-eula/psn/<path:subpath>', methods=['POST'])
def legal_doc():
    with open('privacy.dat', 'rb') as f:
        data = f.read()
    return Response(data, mimetype='text/plain', headers={
        'X-NativeBuildVersion': '20.00.00.00',
        'X-NativeResult': '0',
    })


# ─── XMB ─────────────────────────────────────────────────────────────

# put the damm Update list xml  (working and not for this category (its for xmb to know if a app have a update or no))
@app.route('/tpl/np/<path:subpath>', methods=['POST'])
def update_game(subpath):
    filename = os.path.basename(subpath)
    local_path = os.path.join('xml', 'updat', filename)

    if os.path.exists(local_path):
        with open(local_path, 'rb') as f:
            data = f.read()
    else:
        base_name = filename.replace('-ver.xml', '')
        url = f'https://a0.ww.np.dl.playstation.net/tpl/np/{base_name}/{filename}'
        
        os.makedirs(os.path.join('xml', 'updat'), exist_ok=True)

        result = subprocess.run(
            ['wget', '--no-check-certificate', '-O', local_path, url],
            capture_output=True
        )

        if result.returncode != 0 or not os.path.exists(local_path):
            return Response('Not Found', status=404)

        with open(local_path, 'rb') as f:
            data = f.read()

    return Response(data, mimetype='text/xml')

# ─── NSX LOGGING ─────────────────────────────────────────────────────────────
#!!IMPORTANT!! please stop saying nsx is only for logging / spying, nsx-e and nsx also deliver content to the ps3 

HTTP_CODES = {
    100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
    200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
    204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect", 310: "Too Many Redirects",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 408: "Request Timeout", 409: "Conflict", 410: "Gone",
    413: "Request Entity Too Large", 415: "Unsupported Media Type", 418: "I'm a teapot",
    429: "Too Many Requests",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported",
}

@app.route('/nsx/log', methods=['GET', 'POST'])
def nsx_log():
    sid = request.args.get('sid', 'unknown')
    t   = request.args.get('t', '?')
    c   = request.args.get('c', '?')
    l   = request.args.get('l', '?')
    e   = request.args.get('e', None)

    print(f"\n[NSX LOG] {'='*40}")
    print(f"  Session ID : {sid}")
    print(f"  Time taken : {t}ms")
    print(f"  Country    : {c}")
    print(f"  Level      : {l}")
    if e:
        code = int(e) if e.isdigit() else None
        desc = HTTP_CODES.get(code, "Unknown") if code else "Unknown"
        print(f"  HTTP Error : {e} - {desc}")
    print(f"{'='*44}\n")

    return Response('OK', status=200)


# ─── Other Routes  ────────────────────────────────────────────────────────────
#all of this join the untested and probably broken route of dispair
@app.route('/ecomm/ingame/getIngameProducts', methods=['POST'])
def get_ingame_products():
    return Response('<?xml version="1.0"?><products></products>', mimetype='text/xml')

@app.route('/ecomm/ingame/setAccountDataFlags', methods=['POST'])
def set_account_flags():
    return Response('OK', status=200)

@app.route('/ecomm/ingame/getAccountDataFlags', methods=['POST'])
def get_account_flags():
    return Response('flaglist=0', status=200)

@app.route('/ranking_view/func/get_ranking', methods=['GET', 'POST'])
def get_ranking():
    return Response('<?xml version="1.0"?><ranking><list></list></ranking>', mimetype='text/xml')

@app.route('/user_storage/sec/get_data', methods=['GET', 'POST'])
def get_storage():
    return Response('<?xml version="1.0"?><npstorage><data></data></npstorage>', mimetype='text/xml')

@app.route('/np/resource/friendlist/friendlist-status.xml', methods=['GET'])
def friendlist_status():
    return Response('<?xml version="1.0"?><friendlist><status>alive</status></friendlist>', mimetype='text/xml')

# ─── Catch all system  ────────────────────────────────────────────────────────────
#so even if something doesnt exist you get a nice page that tell you to go fu- kindly get off the page :D
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    print(f"[UNKNOWN] {request.method} /{path}")
    return Response('Not found', status=404)

# ─── Main ─────────────────────────────────────────────────────────────────────
# yup all we need is http baby (on my version of the modified sprx file i pass every https endpoint to http [no it doesnt break things (surprisingly)])
if __name__ == '__main__':
    print("PSN - recreated by legamer")
    #print("[DB]: Starting...")
    #init_db()
    #print("[DB]: Done")
    print("[HTTP]: Listening on port 80")
    app.run(host='0.0.0.0', port=80, debug=False)
