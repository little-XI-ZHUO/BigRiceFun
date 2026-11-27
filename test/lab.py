"""Local lab for the Web risk audit. Loopback only, one known answer per port.

port  mode            expected result
18081 form_weak       弱口令 admin/admin（表单，302 -> /home）
18082 form_strong     nothing (wrong-password control)
18083 basic_root      弱口令 admin/admin（HTTP Basic on /）
18084 basic_tomcat    弱口令 tomcat/s3cret（Basic on /manager/html）
18085 actuator        Actuator env + heapdump + mappings + beans + 端点列表
18086 swagger_druid   Swagger UI + Druid 监控
18087 nacos           Nacos 用户 + 配置未授权
18088 docker          Docker API 未授权 (version + containers)
18089 captcha         信息: 登录口有验证码
18090 lockout         信息: 触发锁定保护（应尽早停手）
18091 digest_root     弱口令 admin/12345（HTTP Digest on /）
18092 backup          备份文件可下载 /www.zip
18093 spa_fallback    nothing (every path returns 200 index.html)
18094 index_of        目录浏览
18095 device_js       弱口令 admin/admin（嵌入式设备：无 <form>，登录页在 /login.htm，JS 提交返回 JSON）
18096 device_strong   nothing (同上结构，但只有强口令 — 误报对照)
18099 closed          no row at all
"""
import base64
import functools
import hashlib
import http.server
import json
import re
import ssl
import sys
import threading
import time
import uuid
from urllib.parse import parse_qs

HOST = "127.0.0.1"
LAB = {
    18081: ("form_weak", {"admin": "admin"}),
    18082: ("form_strong", {"admin": "NOPE"}),
    18083: ("basic_root", {"admin": "admin"}),
    18084: ("basic_tomcat", {"tomcat": "s3cret"}),
    18085: ("actuator", {}),
    18086: ("swagger_druid", {}),
    18087: ("nacos", {}),
    18088: ("docker", {}),
    18089: ("captcha", {}),
    18090: ("lockout", {"root": "root"}),
    18091: ("digest_root", {"admin": "12345"}),
    18092: ("backup", {}),
    18093: ("spa_fallback", {}),
    18094: ("index_of", {}),
    18095: ("device_js", {"admin": "admin"}),
    18096: ("device_strong", {"admin": "NOPE"}),
}
PAGE = "<!doctype html><html><head><meta charset='utf-8'><title>%s</title></head><body>%s</body></html>"
WRONG = {}
ZIP_BYTES = b"PK\x03\x04" + bytes(2048) + b"PK\x05\x06" + bytes(18)

# 嵌入式设备风格的登录页：没有 <form>，散落的 input，JS 发 POST /api/login 拿 JSON。
# 首页是欢迎页，带一个指向 /login.htm 的链接。模拟 Mongoose 类设备的真实结构。
DEVICE_INDEX = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>设备首页</title></head>
<body><h1>设备欢迎页面</h1><a href="/login.htm">进入登录</a></body></html>"""
DEVICE_LOGIN = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>登录</title>
<style>body{background:#111;color:#eee;font-family:sans-serif}</style></head>
<body><div id="login"><h2>欢迎登录</h2>
<input type="text" id="username" placeholder="用户名" value="admin">
<input type="password" id="password" placeholder="密码">
<button id="btn" onclick="doLogin()">登 录</button></div>
<script src="/static/jquery.min.js"></script>
<script>
function doLogin() {
  $.ajax({ url: "/api/login", type: "POST", dataType: "json",
    data: { username: $("#username").val(), password: $("#password").val() },
    success: function(r) { if (r.success) { location.href = "/index.htm"; } else { alert(r.msg); } } });
}
</script></body></html>"""
DEVICE_SESSION = {}


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def login_form(msg="请登录", captcha=False):
    cap = '<input type="text" name="validateCode"><img src="/captcha.jpg">' if captcha else ""
    note = "<p>%s</p>" % msg if msg else ""
    return PAGE % ("业务系统登录", "%s<form action=\"/login\" method=\"post\">"
                   "<input type=\"text\" name=\"username\">"
                   "<input type=\"password\" name=\"password\">"
                   "<input type=\"hidden\" name=\"_csrf\" value=\"t-%s\">%s<button>登录</button></form>"
                   % (note, uuid.uuid4().hex[:6], cap))


def challenge_digest(realm):
    nonce = uuid.uuid4().hex
    return ('Digest realm="%s", qop="auth", nonce="%s", opaque="%s", algorithm=MD5'
            % (realm, nonce, uuid.uuid4().hex))


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, mode, creds, request, client_address, server):
        self.mode = mode
        self.creds = creds
        try:
            http.server.BaseHTTPRequestHandler.__init__(self, request, client_address, server)
        except (ConnectionError, ValueError, TimeoutError, ssl.SSLError):
            pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ValueError, UnicodeDecodeError, ConnectionError, TimeoutError, ssl.SSLError):
            self.close_connection = True

    def log_request(self, code="-", size="-"):
        sys.stdout.write("%s [%d] %s %s -> %s\n" % (
            time.strftime("%H:%M:%S") + ".%03d" % (time.time_ns() // 1_000_000 % 1000),
            self.server.server_address[1], self.command, self.path[:70], code))
        sys.stdout.flush()

    def _send(self, code, body="", headers=(), ctype="text/html; charset=utf-8"):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD" and raw:
            self.wfile.write(raw)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj), ctype="application/json")

    def _basic(self, realm):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            self._send(401, headers=[("WWW-Authenticate", 'Basic realm="%s"' % realm)])
            return None
        try:
            u, _, p = base64.b64decode(auth[6:]).decode().partition(":")
        except Exception:
            u = p = ""
        return (u, p)

    def _digest(self, realm):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Digest "):
            self._send(401, headers=[("WWW-Authenticate", challenge_digest(realm))])
            return None
        kv = {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3))
              for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,]*))', auth[7:])}
        ha2 = md5("%s:%s" % (self.command, kv.get("uri", "")))
        for u, p in self.creds.items():
            ha1 = md5("%s:%s:%s" % (u, realm, p))
            want = md5("%s:%s:%s:%s:%s:%s" % (ha1, kv.get("nonce", ""), kv.get("nc", ""),
                                              kv.get("cnonce", ""), kv.get("qop", "auth"), ha2))
            if kv.get("response") == want and kv.get("username") == u:
                return (u, p)
        self._send(401, headers=[("WWW-Authenticate", challenge_digest(realm))])
        return None

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        m, p = self.mode, self.path.split("?")[0]
        if m == "basic_root":
            ok = self._basic("lab")
            if ok is None:
                return
            if ok in [(u, p2) for u, p2 in self.creds.items()]:
                self._send(200, PAGE % ("内部系统", "hello"))
            else:
                self._send(401, headers=[("WWW-Authenticate", 'Basic realm="lab"')])
        elif m == "digest_root":
            ok = self._digest("lab")
            if ok is None:
                return
            self._send(200, PAGE % ("设备管理", "hello"))
        elif m == "basic_tomcat":
            if p == "/":
                self._send(200, PAGE % ("应用首页", "app"))
            elif p == "/manager/html":
                ok = self._basic("Tomcat Manager Application")
                if ok is None:
                    return
                if ok in [(u, p2) for u, p2 in self.creds.items()]:
                    self._send(200, PAGE % ("Tomcat Manager Application", "apps"))
                else:
                    self._send(401, headers=[("WWW-Authenticate", 'Basic realm="Tomcat Manager Application"')])
            else:
                self._send(404, PAGE % ("404", "not found"))
        elif m == "actuator":
            if p == "/":
                self._send(200, PAGE % ("Spring 演示系统", "home"))
            elif p == "/actuator/env":
                self._json({"activeProfiles": ["prod"], "propertySources": [{"name": "systemProperties"}]})
            elif p == "/actuator/heapdump":
                self._send(200, bytes(8192), ctype="application/octet-stream")
            elif p in ("/actuator/mappings", "/actuator/beans"):
                self._json({"contexts": {"app": {}}})
            elif p == "/actuator":
                self._json({"_links": {"self": {"href": "http://x/actuator"}}})
            else:
                self._send(404, PAGE % ("404", "not found"))
        elif m == "swagger_druid":
            if p == "/":
                self._send(200, PAGE % ("接口平台", "api"))
            elif p == "/swagger-ui.html":
                self._send(200, PAGE % ("Swagger UI", "swagger"))
            elif p == "/druid/index.html":
                self._send(200, PAGE % ("Druid Monitor", '<a href="sql.html">sql.html</a>'))
            else:
                self._send(404, PAGE % ("404", "not found"))
        elif m == "nacos":
            if p == "/":
                self._send(200, PAGE % ("Nacos console", "nacos"))
            elif p.startswith("/nacos/v1/auth/users") or p.startswith("/nacos/v1/cs/configs"):
                self._json({"pageItems": [{"x": 1}], "totalCount": 1, "pageNumber": 1})
            else:
                self._send(404, PAGE % ("404", "not found"))
        elif m == "docker":
            if p in ("/", "/version"):
                self._json({"Version": "20.10", "ApiVersion": "1.41", "MinAPIVersion": "1.12",
                            "GitCommit": "abcd", "GoVersion": "go1.16", "Os": "linux", "Arch": "amd64"})
            elif p.startswith("/containers/json"):
                self._json([{"Names": ["/web"], "Id": "abc", "Image": "nginx"}])
            else:
                self._json({"message": "page not found"}, 404)
        elif m == "captcha":
            if p == "/":
                self._send(200, PAGE % ("普通业务系统", "home"))
            elif p == "/login":
                self._send(200, login_form(captcha=True))
            else:
                self._send(404, PAGE % ("404", "not found"))
        elif m in ("form_weak", "form_strong", "lockout"):
            if p == "/home":
                if "SID=ok" in (self.headers.get("Cookie") or ""):
                    self._send(200, PAGE % ("控制台", "欢迎 admin <a href=/logout>退出登录</a>"))
                else:
                    self._send(302, headers=[("Location", "/")])
            elif p in ("/login", "/"):
                self._send(200, login_form())
            else:
                self._send(404, PAGE % ("404", "not found"))
        elif m == "backup":
            if p == "/www.zip":
                self._send(200, ZIP_BYTES, ctype="application/zip")
            elif p == "/":
                self._send(200, PAGE % ("企业门户", "portal"))
            else:
                self._send(404, PAGE % ("404", "not found"))
        elif m == "spa_fallback":
            self._send(200, PAGE % ("单页应用", "app root"))
        elif m == "index_of":
            self._send(200, "<html><head><title>Index of /</title></head><body><a href=old/>old/</a></body></html>")
        elif m in ("device_js", "device_strong"):
            # 嵌入式设备：首页欢迎页 -> /login.htm 登录页；其它路径 404
            if p in ("/", "/index.html", "/index.htm"):
                self._send(200, DEVICE_INDEX, headers=[("Server", "Mongoose/6.18")])
            elif p in ("/login.htm", "/login.html"):
                self._send(200, DEVICE_LOGIN, headers=[("Server", "Mongoose/6.18")])
            elif p.startswith("/static/"):
                self._send(200, "/*stub*/", ctype="application/javascript", headers=[("Server", "Mongoose/6.18")])
            else:
                self._send(404, PAGE % ("404", "not found"), headers=[("Server", "Mongoose/6.18")])
        else:
            self._send(404, PAGE % ("404", "not found"))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        q = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        u = (q.get("username") or [""])[0]
        p = (q.get("password") or [""])[0]
        if self.mode in ("device_js", "device_strong") and self.path.startswith("/api/login"):
            # 和真实设备一样：JSON 应答，成功时带 token，失败时 success:false
            ok = self.creds.get(u) == p
            body = (json.dumps({"success": True, "token": "sess-" + uuid.uuid4().hex[:8]})
                    if ok else json.dumps({"success": False, "msg": "用户名或密码错误"}))
            self._send(200, body, ctype="application/json", headers=[("Server", "Mongoose/6.18")])
            return
        if self.mode in ("form_weak", "form_strong", "lockout") and self.path.startswith("/login"):
            key = (self.server.server_address[1], u)
            if self.mode == "lockout" and WRONG.get(key, 0) >= 3:
                self._send(200, login_form("账号已锁定，请联系管理员"))
                return
            if self.creds.get(u) == p:
                self._send(302, headers=[("Location", "/home"), ("Set-Cookie", "SID=ok; Path=/")])
                return
            WRONG[key] = WRONG.get(key, 0) + 1
            self._send(200, login_form("用户名或密码错误"))
            return
        self._send(404, PAGE % ("404", "not found"))


def serve(port, mode, creds):
    srv = http.server.ThreadingHTTPServer((HOST, port), functools.partial(H, mode, creds))
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == "__main__":
    for port, (mode, creds) in sorted(LAB.items()):
        threading.Thread(target=serve, args=(port, mode, creds), daemon=True).start()
        print("listening %d %s" % (port, mode), flush=True)
    print("lab ready", flush=True)
    threading.Event().wait()
