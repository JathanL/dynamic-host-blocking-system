# Dynamic Host Blocking - offline web demo (Python 3, no installs needed)
# Run:  python web_demo.py        then open the links it prints.
import json, secrets, socket, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
LIMIT, WINDOW, EVERY = 15, 10, 5      # max requests per host in WINDOW seconds, checked every EVERY seconds
LOCK = threading.Lock()
HOSTS, LOG = {}, []                   # HOSTS: ip -> info; the "blocked" flag is the blocklist
BLOCK_DEV = set()                     # devices (like MAC addresses) that were blocked
DEV = {"on": True}                   # device blocking switch
TC = {"id": 0, "run": False, "t": 0.0, "verdict": "", "results": {}}


def log(msg):
    line = time.strftime("%H:%M:%S") + "  " + msg
    LOG.insert(0, line)
    del LOG[80:]
    with open("web_events.log", "a") as f:
        f.write(line + "\n")
    print(line)


def hit(key, name=None, ip=None, dev=None):
    """One request from a host. Returns False if the host is blocked (request dropped)."""
    with LOCK:
        h = HOSTS.get(key)
        if h is None:
            h = HOSTS[key] = {"ip": ip or key, "name": name or ip or key, "hits": [], "blocked": False, "dropped": 0, "total": 0, "dev": dev}
            log("NEW HOST %s (%s)" % (h["name"], h["ip"]))
        if name:
            h["name"] = name
        if not h["blocked"] and DEV["on"] and dev and dev in BLOCK_DEV:
            h["blocked"] = True
            h["bt"] = TC["t"]
            log("BLOCKED %s (%s): same device as an already blocked host" % (h["name"], h["ip"]))
        if h["blocked"]:
            h["dropped"] += 1
            return False
        h["hits"].append(time.time())
        h["total"] += 1
        return True


def recent(h):
    now = time.time()
    h["hits"] = [t for t in h["hits"] if now - t < WINDOW]
    return len(h["hits"])


def checker():
    while True:
        time.sleep(EVERY)
        with LOCK:
            for h in HOSTS.values():
                if h["blocked"]:
                    continue
                n = recent(h)
                who = "%s (%s)" % (h["name"], h["ip"])
                if n:
                    log("host %s has %d connections" % (who, n))
                if n > LIMIT:
                    h["blocked"] = True
                    h["bt"] = TC["t"]
                    if h.get("dev"):
                        BLOCK_DEV.add(h["dev"])
                    log("BLOCKED %s (%d connections)" % (who, n))


# ---- automatic test cases: (title, description, seconds, actors, who must be blocked, earliest block time)
def seg(rate, a, b): return (a, b, rate)
SCN = {
 1: ("Normal users only", "Two normal users send one request every few seconds.", 25,
     [("10.0.0.2", "Normal user 1", [seg(0.33, 0, 25)]), ("10.0.0.4", "Normal user 2", [seg(0.2, 0, 25)])], [], 0),
 2: ("One attacker among normal users", "Attacker sends 8 requests per second while a normal user stays slow.", 20,
     [("10.0.0.2", "Normal user", [seg(0.33, 0, 20)]), ("10.0.0.3", "Attacker 1", [seg(8, 0, 20)])], ["Attacker 1"], 0),
 3: ("Multiple attackers", "Three attackers at different speeds attack together with one normal user.", 20,
     [("10.0.0.2", "Normal user", [seg(0.33, 0, 20)]), ("10.0.0.3", "Attacker 1", [seg(8, 0, 20)]),
      ("10.0.0.5", "Attacker 2", [seg(5, 0, 20)]), ("10.0.0.6", "Attacker 3", [seg(12, 0, 20)])],
     ["Attacker 1", "Attacker 2", "Attacker 3"], 0),
 4: ("Normal first, attacker later", "Host behaves normally for 12 s, then suddenly turns into an attacker.", 30,
     [("10.0.0.2", "Normal user", [seg(0.33, 0, 30)]), ("10.0.0.3", "Host A (turns bad)", [seg(0.33, 0, 12), seg(8, 12, 30)])],
     ["Host A (turns bad)"], 12),
 5: ("Boundary: exactly 15 vs 16", "Two hosts each send one quick burst: 15 requests and 16 requests.", 20,
     [("10.0.0.2", "Host B15 (15 requests)", [seg(15, 1, 2)]), ("10.0.0.3", "Host B16 (16 requests)", [seg(16, 1, 2)])],
     ["Host B16 (16 requests)"], 0),
}


def run_tc(n):
    global LIMIT
    title, desc, dur, actors, expect, min_t, *rest = SCN[n]
    with LOCK:
        HOSTS.clear()
        del LOG[:]
        BLOCK_DEV.clear()
    LIMIT = 15
    TC.update(id=n, run=True, t=0.0, verdict="")
    log("TEST CASE %d started: %s" % (n, title))
    ev = []
    for act in actors:
        ip, name, segs = act[0], act[1], act[2]
        dv = act[3] if len(act) > 3 else None
        for s in segs:
            a, b, r = s[0], s[1], s[2]
            ip2, name2 = (s[3], s[4]) if len(s) > 4 else (ip, name)
            ev += [(a + k / r, ip2, name2, dv) for k in range(int(round((b - a) * r)))]
    ev.sort()
    t0, i = time.time(), 0
    while TC["id"] == n and TC["run"] and time.time() - t0 < dur:
        TC["t"] = time.time() - t0
        while i < len(ev) and ev[i][0] <= TC["t"]:
            hit(ev[i][1], ev[i][2], ev[i][1], ev[i][3])
            i += 1
        time.sleep(0.02)
    if TC["id"] != n or not TC["run"]:
        return
    with LOCK:
        blocked = {h["name"]: h.get("bt", 0) for h in HOSTS.values() if h["blocked"]}
        totals = {h["name"]: h["total"] for h in HOSTS.values()}
    zero = rest[0] if rest else []
    ok = set(blocked) == set(expect) and all(v >= min_t for v in blocked.values()) and all(totals.get(z, 0) == 0 for z in zero)
    TC["verdict"] = "PASS" if ok else "FAIL"
    TC["results"][n] = TC["verdict"]
    TC["run"] = False
    log("TEST CASE %d result: %s (blocked: %s)" % (n, TC["verdict"], ", ".join(sorted(blocked)) or "nobody"))


SCN[6] = ("Attacker changes IP address (real life)", "Attacker is blocked, then returns with a NEW IP address from the same device. The device (MAC) block must stop it at once.", 30,
          [("10.0.0.2", "Normal user", [seg(0.33, 0, 30)]),
           ("10.0.0.3", "Attacker (10.0.0.3)", [(0, 10, 8), (14, 28, 8, "10.0.0.33", "Attacker (new IP 10.0.0.33)")], "dev-A")],
          ["Attacker (10.0.0.3)", "Attacker (new IP 10.0.0.33)"], 0, ["Attacker (new IP 10.0.0.33)"])


def tc_info():
    n = TC["id"]
    if n not in SCN:
        return {"id": 0}
    title, desc, dur, actors, expect, min_t, *rest = SCN[n]
    return {"id": n, "title": title, "desc": desc, "dur": dur, "run": TC["run"], "t": TC["t"], "verdict": TC["verdict"],
            "expect": "blocked: " + (", ".join(expect) or "nobody") + ("; allowed until the behaviour changes" if min_t else "")}


CSS = """
*{box-sizing:border-box}body{margin:0;font:15px/1.5 "Segoe UI",system-ui,sans-serif;color:#E5ECF6;background:#0A0E1A radial-gradient(900px 420px at 85% -10%,rgba(167,139,250,.2),transparent) no-repeat}
.w{max-width:980px;margin:0 auto;padding:20px 16px 40px}h1{font-size:22px;margin:0 0 4px}.m{color:#94A3B8}
.c{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.13);border-radius:14px;padding:16px;margin-bottom:14px}
h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#38BDF8;margin:0 0 10px}
input[type=text]{width:100%;padding:11px;border-radius:10px;border:1px solid rgba(255,255,255,.2);background:transparent;color:#E5ECF6;font:inherit}
button{border:0;border-radius:12px;padding:12px 18px;font:inherit;font-weight:700;cursor:pointer;background:#38BDF8;color:#0A0E1A}
button.s{background:transparent;border:1px solid rgba(255,255,255,.25);color:#E5ECF6}button:disabled{opacity:.4;cursor:not-allowed}
button.big{width:100%;font-size:22px;padding:34px 18px;margin:8px 0}
.b{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;font-size:13px}.ok{background:rgba(52,211,153,.18);color:#34D399}.bad{background:rgba(251,113,133,.2);color:#FB7185}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:760px){.g2{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid rgba(255,255,255,.12);white-space:nowrap}th{color:#94A3B8}
.bar{height:8px;border-radius:6px;background:rgba(255,255,255,.15);min-width:90px;overflow:hidden}.bar i{display:block;height:100%}
.mono{font-family:Consolas,monospace;font-size:12.5px}#log{max-height:260px;overflow:auto}#log div{padding:2px 0;border-bottom:1px dashed rgba(255,255,255,.12)}.r{color:#FB7185;font-weight:700}
"""

VISITOR = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Host Blocking Demo</title><style>""" + CSS + """</style></head><body><div class="w">
<h1>Dynamic Host Blocking: Visitor</h1><div class="m">Press ENTER to send a request to the server. Slowly is fine. Too fast and the controller blocks you.</div><br>
<div class="c"><input type="text" id="nm" maxlength="20" placeholder="Your name (optional)"></div>
<div class="c"><div class="row" style="justify-content:space-between"><b>Your address: <span id="ip">...</span></b><span class="b ok" id="st">ALLOWED</span></div>
<button class="big" id="go">ENTER (send request)</button>
<div class="m">Requests in the last 10 s: <b id="n">0</b></div><p id="msg"></p></div></div>
<script>
var blocked=false;
function upd(d){blocked=d.blocked;document.getElementById('n').textContent=d.n;var s=document.getElementById('st');
 s.textContent=blocked?'BLOCKED':'ALLOWED';s.className='b '+(blocked?'bad':'ok');document.getElementById('go').disabled=blocked;
 document.getElementById('msg').innerHTML=blocked?'<span class="r">You were blocked by the controller. Your requests are dropped.</span>':'';}
document.getElementById('go').onclick=function(){if(blocked)return;
 fetch('/api/enter',{method:'POST',body:JSON.stringify({name:document.getElementById('nm').value.trim()})}).then(function(r){return r.json()}).then(upd).catch(function(){});};
setInterval(function(){fetch('/api/me').then(function(r){return r.json()}).then(function(d){document.getElementById('ip').textContent=d.ip;upd(d)}).catch(function(){});},700);
</script></body></html>"""

DASH = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Controller Dashboard</title><style>""" + CSS + """</style></head><body><div class="w">
<h1>Controller Dashboard</h1><div class="m">Visitors are hosts. The controller counts requests per host and blocks any host over the limit.</div><br>
<div class="c"><h2>Test cases (automatic simulation)</h2><div class="row" id="tcb"></div><div id="tci" style="margin:12px 0"></div><div class="row"><button class="s" id="rst">Reset all</button><button class="s" id="dvb">Device (MAC) blocking: ON</button>
<label class="m">Limit: <b id="lv">15</b> requests per 10 s <input type="range" id="lim" min="2" max="30" value="15"></label></div></div>
<div class="c"><h2>Hosts seen by the controller</h2><div style="overflow-x:auto"><table><thead><tr><th>Host</th><th>Address</th><th>Requests (10 s)</th><th>Load vs limit</th><th>Status</th></tr></thead><tbody id="tb"></tbody></table></div></div>
<div class="g2"><div class="c"><h2>Switch flow table</h2><div class="mono" id="ft"></div></div><div class="c"><h2>Controller log</h2><div class="mono" id="log"></div></div></div>
<div class="m" style="font-size:12.5px">Blocking here is done by the web server using each visitor's real network address. Real packet drops are shown in the Mininet and Ryu demo.</div></div>
<script>
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function post(p,d){return fetch(p,{method:'POST',body:JSON.stringify(d||{})})}
document.getElementById('tcb').onclick=function(e){var n=e.target.getAttribute('data-n');if(n)post('/api/tc',{n:+n})};document.getElementById('rst').onclick=function(){post('/api/reset')};
document.getElementById('dvb').onclick=function(){post('/api/dev',{on:!window._dev})};document.getElementById('lim').oninput=function(e){document.getElementById('lv').textContent=e.target.value;post('/api/limit',{limit:+e.target.value})};
function tcdraw(d){window._dev=d.dev;document.getElementById('dvb').textContent='Device (MAC) blocking: '+(d.dev?'ON':'OFF');var b='';d.list.forEach(function(x){var r=d.results[x[0]]||'';b+='<button data-n="'+x[0]+'" class="'+(d.tc.id==x[0]&&d.tc.run?'':'s')+'">TC'+x[0]+' '+esc(x[1])+(r?' ['+r+']':'')+'</button>';});
 var el=document.getElementById('tcb');if(el.getAttribute('data-k')!==b){el.innerHTML=b;el.setAttribute('data-k',b);}
 var t=d.tc;document.getElementById('tci').innerHTML=t.id?('<b>'+esc(t.title)+'</b>: '+esc(t.desc)+'<br><span class="m">Expected: '+esc(t.expect)+'</span><br>'+(t.run?'Running: '+t.t.toFixed(0)+' s of '+t.dur+' s':'Finished')+(t.verdict?' <span class="b '+(t.verdict=='PASS'?'ok':'bad')+'">'+t.verdict+'</span>':'')):'<span class="m">Pick a test case to simulate hosts automatically, or share the link and let real friends join.</span>';}
function draw(){fetch('/api/status').then(function(r){return r.json()}).then(function(d){
 tcdraw(d);var h='',f='';d.hosts.forEach(function(x){var p=Math.min(100,x.n/d.limit*100),c=p>=100?'#FB7185':p>60?'#FBBF24':'#34D399';
  h+='<tr><td>'+esc(x.name)+'</td><td class="m">'+esc(x.ip)+'</td><td>'+x.n+'</td><td><div class="bar"><i style="width:'+p+'%;background:'+c+'"></i></div></td><td><span class="b '+(x.blocked?'bad':'ok')+'">'+(x.blocked?'BLOCKED':'ALLOWED')+'</span></td></tr>';
  if(x.blocked)f+='<div class="r">priority=100 src='+esc(x.ip)+' actions=drop n_packets='+x.dropped+'</div>';});
 document.getElementById('tb').innerHTML=h||'<tr><td colspan="5" class="m">Nobody yet. Pick a test case or share the link.</td></tr>';
 document.getElementById('ft').innerHTML=f+'<div class="m">priority=0 actions=CONTROLLER</div>';
 document.getElementById('lv').textContent=d.limit;document.getElementById('lim').value=d.limit;
 document.getElementById('log').innerHTML=d.log.map(function(l){return '<div>'+(l.indexOf('BLOCKED')>-1?'<span class="r">'+esc(l)+'</span>':esc(l))+'</div>'}).join('');}).catch(function(){});}
setInterval(draw,500);draw();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="application/json", extra=None):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def via_tunnel(self):
        return any(self.headers.get(h) for h in ("CF-Connecting-IP", "X-Forwarded-For", "CF-Ray"))

    def local(self):
        # dashboard and controls: only from this computer, never through the tunnel
        return self.client_address[0] in ("127.0.0.1", "::1") and not self.via_tunnel()

    def who(self):
        """Real address of the visitor (works behind the tunnel) + a per-browser id."""
        ip = (self.headers.get("CF-Connecting-IP")
              or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
              or self.client_address[0])
        hid = ""
        for part in (self.headers.get("Cookie") or "").split(";"):
            if part.strip().startswith("hid="):
                hid = "".join(c for c in part.strip()[4:] if c.isalnum())[:12]
        return ip, (ip + "#" + hid if hid else ip), hid

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        ip, key, hid = self.who()
        if self.path in ("/", "/index.html"):
            extra = None if hid else {"Set-Cookie": "hid=%s; Path=/; Max-Age=86400; SameSite=Lax" % secrets.token_hex(4)}
            return self.reply(200, VISITOR, "text/html", extra)
        if self.path == "/dashboard":
            if self.local():
                return self.reply(200, DASH, "text/html")
            return self.reply(403, "The dashboard is only available on the host computer.", "text/plain")
        if self.path == "/api/me":
            with LOCK:
                h = HOSTS.get(key)
                return self.reply(200, json.dumps({"blocked": bool(h and h["blocked"]) or bool(DEV["on"] and hid and hid in BLOCK_DEV), "n": recent(h) if h else 0, "ip": ip}))
        if self.path == "/api/status" and self.local():
            with LOCK:
                rows = [{"ip": h["ip"], "name": h["name"], "n": recent(h), "blocked": h["blocked"],
                         "dropped": h["dropped"], "total": h["total"]} for h in HOSTS.values()]
                return self.reply(200, json.dumps({"hosts": rows, "log": LOG[:40], "limit": LIMIT, "dev": DEV["on"], "tc": tc_info(), "results": TC["results"], "list": [[k, v[0]] for k, v in SCN.items()]}))
        self.reply(404, "not found", "text/plain")

    def do_POST(self):
        global LIMIT
        ip, key, hid = self.who()
        d = self.read_json()
        if self.path == "/api/enter":
            name = str(d.get("name", "")).strip()[:20] or None
            ok = hit(key, name, ip, hid or None)
            with LOCK:
                n = recent(HOSTS[key])
            return self.reply(200 if ok else 403, json.dumps({"ok": ok, "blocked": not ok, "n": n}))
        if not self.local():
            return self.reply(403, "{}")
        if self.path == "/api/limit":
            LIMIT = max(2, min(50, int(d.get("limit", 15))))
            log("limit set to %d" % LIMIT)
        elif self.path == "/api/dev":
            DEV["on"] = bool(d.get("on"))
            log("device (MAC) blocking turned %s" % ("ON" if DEV["on"] else "OFF"))
        elif self.path == "/api/tc":
            n = int(d.get("n", 0))
            if n in SCN:
                threading.Thread(target=run_tc, args=(n,), daemon=True).start()
        elif self.path == "/api/reset":
            TC["run"] = False
            TC["id"] = 0
            TC["results"] = {}
            with LOCK:
                HOSTS.clear()
                del LOG[:]
                BLOCK_DEV.clear()
            log("controller reset, blocklist cleared")
        self.reply(200, "{}")


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    threading.Thread(target=checker, daemon=True).start()
    print("\n  Dashboard (open on THIS computer only): http://localhost:%d/dashboard" % PORT)
    print("  Same Wi-Fi visitors                   : http://%s:%d" % (lan_ip(), PORT))
    print("  Friends on their own internet         : open a 2nd window and run")
    print("      ssh -o ServerAliveInterval=60 -R 80:localhost:%d nokey@localhost.run" % PORT)
    print("  then share the https://....lhr.life link it prints.\n")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
