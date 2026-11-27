package com.bigricescan;

import com.webfinder.portscan.model.Row;
import org.apache.http.NameValuePair;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.message.BasicNameValuePair;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 对一个 Web 服务做风险检测：未授权访问特征 + 登录口弱口令（表单 / Basic / Digest）。
 * 只读探测，不写文件、不执行命令；出现锁定保护特征立即停手。
 */
final class WebAudit implements Runnable {
    private static final long BUDGET_MS = 180_000;
    private static final Pattern INDEX_OF = Pattern.compile("(?is)<title[^>]*>\\s*(index of|目录列表)");
    private static final String[] BACKUPS = {"/www.zip", "/web.zip", "/website.zip", "/backup.zip", "/site.zip",
            "/www.rar", "/web.rar", "/backup.rar", "/backup.tar.gz", "/www.tar.gz", "/backup.gz", "/www.gz",
            "/backup.sql", "/database.sql", "/db.sql", "/data.sql", "/www.sql", "/dump.sql", "/1.sql"};
    private static final String[] LIST_DIRS = {"/upload/", "/uploads/", "/backup/", "/data/", "/static/",
            "/file/", "/files/", "/temp/", "/logs/", "/img/"};

    private static final String A_PASS = "修改为高强度口令并启用多因子；启用失败锁定和验证码；管理端只对管理网段开放。";

    private final Boot boot;
    private final Row row;
    private final String addr, base;
    private final boolean doUnauth, doBrute;
    private final RiskInfo info;
    private Http http;
    private long deadline;
    private int fails;

    WebAudit(Boot boot, Row row, String addr, boolean ssl, boolean doUnauth, boolean doBrute) {
        this.boot = boot;
        this.row = row;
        this.addr = addr;
        this.base = (ssl ? "https://" : "http://") + addr;
        this.doUnauth = doUnauth;
        this.doBrute = doBrute;
        this.info = new RiskInfo(addr);
    }

    @Override
    public void run() {
        deadline = System.currentTimeMillis() + BUDGET_MS;
        try (Http h = new Http(5000)) {
            http = h;
            Http.Resp root = http.get(url("/"), null);
            if (root.status == 0) {
                return; // 端口已不可达，扫描器刚抓到页面的瞬间服务停了
            }
            passive(root);
            if (doUnauth) {
                unauth(root);
            }
            if (doBrute) {
                weak(root);
            }
        } catch (Exception e) {
            // 单个目标出错不影响其它目标
        } finally {
            boot.finish(row, info);
        }
    }

    private String url(String path) {
        return base + path;
    }

    private Http.Resp get(String path) {
        if (over()) {
            return null;
        }
        Http.Resp r = http.get(url(path), null);
        count(r);
        return r;
    }

    private void count(Http.Resp r) {
        fails = (r == null || r.status == 0) ? fails + 1 : 0;
    }

    private boolean over() {
        return Thread.currentThread().isInterrupted() || System.currentTimeMillis() > deadline || fails >= 4;
    }

    private void add(String sev, String type, String title, String url, String account, String password,
                     String evidence, String advice) {
        info.add(new RiskItem(sev, type, title, url, account, password, evidence, advice));
    }

    // ---------------- 首页上直接能看出来的 ----------------

    private void passive(Http.Resp root) {
        String body = root.body == null ? "" : root.body;
        String low = body.toLowerCase();
        if (INDEX_OF.matcher(body).find()) {
            add("中危", "未授权访问", "目录浏览", url("/"), null, null,
                    "首页即目录列表：" + clip(Form.title(body), 60), "关闭目录列表（nginx autoindex off / Apache Options -Indexes）。");
        }
        if (low.contains("\"cluster_name\"")) {
            add("高危", "未授权访问", "Elasticsearch 未授权", url("/"), null, null,
                    "根路径返回集群信息：" + clip(body, 120), "9200 只对内网管理段开放，并启用认证。");
        }
        if (low.contains("kibana") || root.headers.containsKey("kbn-name")) {
            Http.Resp r = get("/api/status");
            if (r != null && r.status == 200 && r.body.contains("\"version\"")) {
                add("高危", "未授权访问", "Kibana 未授权", url("/api/status"), null, null,
                        "/api/status 无需登录即可访问：" + clip(r.body, 120), "启用 X-Pack 安全认证，或限制来源网段。");
            }
        }
        if (low.contains("nacos")) {
            nacosUsers("");
        }
    }

    // ---------------- 未授权访问 ----------------

    private void unauth(Http.Resp root) {
        for (Rules.Rule rule : Rules.UNAUTH) {
            if (over()) {
                break;
            }
            Http.Resp r = rule.head ? http.send("HEAD", url(rule.path), null, null, null, null) : get(rule.path);
            if (rule.hit(r)) {
                String ev = rule.head
                        ? "HTTP 200，Content-Type " + r.contentType + "，大小 "
                        + (r.contentLength > 0 ? r.contentLength + " 字节" : "未知")
                        : "HTTP 200，命中特征 " + rule.matched(r) + "；响应片段：" + clip(r.body, 160);
                add(rule.sev, "未授权访问", rule.title, url(rule.path), null, null, ev, rule.fix);
            }
        }
        if (lower(root.body).contains("nacos")) {
            nacosUsers("");
        }
        backups();
        listing();
    }

    private void nacosUsers(String prefix) {
        String[][] probes = {
                {"/v1/auth/users?pageNo=1&pageSize=1", "Nacos 用户信息未授权"},
                {"/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=1", "Nacos 配置信息未授权"}};
        for (String[] p : probes) {
            Http.Resp r = get(prefix + p[0]);
            if (r != null && r.status == 200 && r.body.contains("pageItems")) {
                add("严重", "未授权访问", p[1] + "（根路径即 Nacos）", url(prefix + p[0]), null, null,
                        "HTTP 200，命中特征 pageItems；响应片段：" + clip(r.body, 120), Rules.A_CONSOLE);
            }
        }
    }

    private void backups() {
        for (String p : BACKUPS) {
            if (over()) {
                return;
            }
            boolean sql = p.endsWith(".sql");
            Http.Resp r = sql ? get(p) : http.send("HEAD", url(p), null, null, null, null);
            if (r == null || r.status != 200) {
                continue;
            }
            String ct = r.contentType.toLowerCase();
            boolean hit = sql
                    ? r.body.contains("CREATE TABLE") || r.body.contains("INSERT INTO")
                    : ct.contains("zip") || ct.contains("rar") || ct.contains("octet-stream")
                    || ct.contains("gzip") || ct.contains("tar") || ct.contains("7z")
                    || r.contentLength > 512 * 1024;
            if (hit) {
                add("严重", "未授权访问", "备份文件可下载：" + p, url(p), null, null,
                        "HTTP " + r.status + "，类型 " + r.contentType + "，大小 "
                                + (r.contentLength > 0 ? r.contentLength + " 字节" : "未知"),
                        "立即删除 Web 目录下的备份文件，并核查是否已被下载。");
            }
        }
    }

    private void listing() {
        StringBuilder paths = new StringBuilder();
        int n = 0;
        for (String p : LIST_DIRS) {
            if (over()) {
                break;
            }
            Http.Resp r = get(p);
            if (r != null && r.status == 200 && INDEX_OF.matcher(r.body).find()) {
                if (n++ > 0) {
                    paths.append("、");
                }
                paths.append(p);
            }
        }
        if (n > 0) {
            add("中危", "未授权访问", "目录浏览：" + paths, url(paths.substring(0, paths.indexOf("、") > 0 ? paths.indexOf("、") : paths.length())),
                    null, null, n + " 个路径可直接浏览目录内容：" + paths,
                    "关闭目录列表（nginx autoindex off / Apache Options -Indexes）。");
        }
    }

    // ---------------- 弱口令 ----------------

    private void weak(Http.Resp root) {
        boolean found = false;
        if (root.status == 401 && !root.wwwAuth.isEmpty()) {
            found = tryAuth(pathOf(root), root.wwwAuth);
        }
        if (!found) {
            for (String p : Rules.AUTH_PATHS) {
                if (over()) {
                    break;
                }
                Http.Resp r = get(p);
                if (r == null || r.status != 401 || r.wwwAuth.isEmpty()) {
                    continue;
                }
                if (tryAuth(p, r.wwwAuth)) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            formLogin(root);
        }
    }

    private String pathOf(Http.Resp r) {
        String u = r.finalUrl;
        if (u.startsWith(base)) {
            String p = u.substring(base.length());
            return p.isEmpty() ? "/" : (p.startsWith("/") ? p : "/" + p);
        }
        return "/";
    }

    /** HTTP Basic / Digest 认证的弱口令：带上凭据后不再是 401 即成功。 */
    private boolean tryAuth(String path, String challenge) {
        String scheme = challenge.toLowerCase().startsWith("digest") ? "Digest" : "Basic";
        String full = url(path);
        for (final String[] up : Rules.pairsForAuth(path)) {
            if (over()) {
                break;
            }
            Http.Creds c = new Http.Creds() {
                @Override
                public String user() {
                    return up[0];
                }

                @Override
                public String pass() {
                    return up[1];
                }
            };
            Http.Resp r = http.send("GET", full, null, c, new BasicCookieStore(), null);
            if (r.status >= 200 && r.status < 400) {
                String t = Form.title(r.body);
                add(Rules.infra(path) ? "严重" : "高危", "弱口令", "弱口令 " + up[0] + "/" + empty(up[1]),
                        full, up[0], up[1],
                        "HTTP " + scheme + " 认证通过，返回 " + r.status + (t.isEmpty() ? "" : "，页面标题 " + t),
                        A_PASS);
                return true;
            }
        }
        return false;
    }

    /** 表单登录的弱口令：先用随机账号打一遍当基线，再逐组比较差异。 */
    private void formLogin(Http.Resp root) {
        String page = null;
        String pageUrl = null;
        // 1) 首页本身就是登录页
        if (root.status == 200 && Form.hasPassword(root.body)) {
            page = root.body;
            pageUrl = root.finalUrl;
        } else {
            // 2) 逐个试登录路径。注意：有的站 302 到 login 页，get() 已经跟过去了，所以要看跟过去的页面
            for (String p : Rules.LOGIN_PATHS) {
                if (over()) {
                    break;
                }
                Http.Resp r = get(p);
                if (r == null || r.status != 200 || !Form.hasPassword(r.body)) {
                    continue;
                }
                page = r.body;
                pageUrl = r.finalUrl;
                break;
            }
        }
        // 3) 首页有指向登录页的链接（<a href="/login.htm">、location.href="login.htm"），顺着找
        if (page == null && root.status == 200) {
            String guess = loginLink(root.body, root.finalUrl);
            if (guess != null && !guess.equalsIgnoreCase(root.finalUrl)) {
                Http.Resp r = get(guess);
                if (r != null && r.status == 200 && Form.hasPassword(r.body)) {
                    page = r.body;
                    pageUrl = r.finalUrl;
                }
            }
        }
        if (page == null) {
            return;
        }
        Form form = Form.parse(pageUrl, page);
        if (form == null) {
            // 看到了密码框但解析不出登录框——至少留条线索，不能静默放过
            add("信息", "弱口令", "发现密码输入框（未能识别登录表单）", pageUrl, null, null,
                    "标题：" + clip(Form.title(page), 60), "人工确认该登录口。");
            return;
        }
        if (form.captcha) {
            add("信息", "弱口令", "登录口有验证码，未自动爆破", form.action, null, null,
                    "标题：" + clip(form.title, 60), "人工确认该登录口的口令强度。");
            return;
        }
        List<String[]> pairs = Rules.pairsForForm(page, form.userField == null);
        Http.Resp base = post(form, junk(), junk(), new BasicCookieStore());
        if (base == null || base.status == 0) {
            add("信息", "弱口令", "发现登录框（提交无响应）", form.action, null, null,
                    "标题：" + clip(form.title, 60) + "；表单：" + form, "人工确认该登录口。");
            return;
        }
        String product = Rules.product(page);
        boolean loginWorks = false;
        for (String[] up : pairs) {
            if (over()) {
                break;
            }
            BasicCookieStore jar = new BasicCookieStore();
            Http.Resp r = post(form, up[0], up[1], jar);
            if (r == null || r.status == 0) {
                continue;
            }
            String verdict = judge(base, r);
            if ("LOCK".equals(verdict)) {
                loginWorks = true;
                add("信息", "弱口令", "登录口触发锁定保护，已停止爆破", form.action, null, null,
                        "出现锁定提示，未再继续尝试", "确认账号是否被锁；该登录口需人工控制节奏。");
                break;
            }
            if (verdict == null) {
                continue;
            }
            String evidence;
            if (r.status >= 300 && r.status < 400) {
                String next = Http.resolve(form.action, r.location);
                Http.Resp after = http.get(next, jar);
                boolean confirmed = after.status == 200 && !Form.hasPassword(after.body);
                if (!confirmed) {
                    continue;
                }
                evidence = "登录返回 " + r.status + " → " + r.location + "，跟随后页面标题："
                        + clip(Form.title(after.body), 60);
            } else {
                // 没有 <form> 的页面（JS 提交）多半返回 JSON，"密码框消失"不足以证明登录成功，
                // 必须出现明确的成功特征才算，否则会误报
                if (form.virtual && "NOPW".equals(verdict)) {
                    continue;
                }
                // 证据如实写判定依据：KW=响应里出现成功标志，NOPW=密码框消失
                if ("KW".equals(verdict)) {
                    String kw = "";
                    for (String k : Rules.SUCCESS_KW) {
                        if (lower(r.body).contains(k)) {
                            kw = k;
                            break;
                        }
                    }
                    evidence = "登录响应出现成功标志 " + kw + "；响应片段：" + clip(r.body, 120);
                } else {
                    String t = clip(Form.title(r.body), 60);
                    evidence = "登录后不再出现密码框" + (t.isEmpty() ? "" : "，页面标题：" + t)
                            + "；响应片段：" + clip(r.body, 120);
                }
            }
            loginWorks = true;
            add(product != null ? "严重" : "高危", "弱口令", "弱口令 " + up[0] + "/" + empty(up[1]), form.action,
                    up[0], up[1], evidence, A_PASS);
            break;
        }
        if (!loginWorks) {
            // 试完了但判不出结果。JS 登录页的提交地址是猜的，猜错就是白试——留条线索让人复核
            add("信息", "弱口令", form.virtual ? "发现 JS 登录框，未能确认口令" : "发现登录框，未发现弱口令",
                    pageUrl, null, null,
                    "表单：" + form + "；试了 " + pairs.size() + " 组" + (form.virtual ? "；提交地址可能猜错" : ""),
                    form.virtual ? "人工确认登录接口后再测。" : "");
        }
    }

    private static final Pattern LOGIN_LINK = Pattern.compile(
            "(?is)(?:href|location(?:\\.href)?|src|url)\\s*[:=]\\s*[\"']([^\"'\\s>]{1,120})[\"']");

    /** 从首页里找指向登录页的链接：路径或文字里带 login/登录，排除当前页。 */
    private String loginLink(String html, String pageUrl) {
        if (html == null) {
            return null;
        }
        Matcher m = LOGIN_LINK.matcher(html);
        while (m.find()) {
            String cand = m.group(1).trim();
            String low = cand.toLowerCase();
            if (cand.startsWith("#") || cand.startsWith("javascript:") || cand.startsWith("data:")
                    || low.endsWith(".css") || low.endsWith(".js") || low.endsWith(".png") || low.endsWith(".jpg")
                    || low.endsWith(".gif") || low.endsWith(".ico") || low.endsWith(".svg")) {
                continue;
            }
            boolean loginish = low.contains("login") || low.contains("signin") || low.contains("logon")
                    || cand.contains("登录") || low.contains("auth");
            if (!loginish) {
                continue;
            }
            String abs = Http.resolve(pageUrl, cand);
            // 去掉锚点
            int h = abs.indexOf('#');
            return h > 0 ? abs.substring(0, h) : abs;
        }
        return null;
    }

    private Http.Resp post(Form form, String user, String pass, BasicCookieStore jar) {
        Form f = form;
        if (form.tokenRefresh) {
            Http.Resp pg = http.get(form.pageUrl, jar);
            if (pg.status == 200) {
                Form fresh = Form.parse(pg.finalUrl, pg.body);
                if (fresh != null) {
                    f = fresh;
                }
            }
        }
        List<NameValuePair> vals = new ArrayList<NameValuePair>();
        for (Map.Entry<String, String> e : f.hidden.entrySet()) {
            vals.add(new BasicNameValuePair(e.getKey(), e.getValue()));
        }
        if (f.userField != null) {
            vals.add(new BasicNameValuePair(f.userField, user));
        }
        vals.add(new BasicNameValuePair(f.passField, pass));
        Http.Resp r = http.send(f.method, f.action, vals, null, jar, f.pageUrl);
        count(r);
        return r;
    }

    /**
     * 判定一次登录的结果。"LOCK" 触发锁定；null 失败或无法判断；其它为成功及依据。
     * 失败/成功特征都要求相对基线新出现，避免页面静态文字干扰。
     */
    static String judge(Http.Resp base, Http.Resp r) {
        String b = lower(r.body);
        String bb = lower(base.body);
        for (String k : Rules.LOCK_KW) {
            if (b.contains(k) && !bb.contains(k)) {
                return "LOCK";
            }
        }
        // 明确的 JSON 成功标志优先判：JS 登录页的基线和结果都是 JSON，都没有密码框，
        // 不先判这里的话后面会因为"两边都没密码框"直接放弃
        if (r.status == 200) {
            for (String k : Rules.SUCCESS_KW) {
                if (b.contains(k) && !bb.contains(k)) {
                    return "KW";
                }
            }
        }
        boolean newFail = false;
        for (String k : Rules.FAIL_KW) {
            if (b.contains(k) && !bb.contains(k)) {
                newFail = true;
                break;
            }
        }
        if (r.status >= 300 && r.status < 400) {
            String loc = r.location.toLowerCase();
            if (r.location.isEmpty() || newFail || loc.equals(base.location.toLowerCase())) {
                return null;
            }
            for (String k : Rules.LOGINISH) {
                if (loc.contains(k)) {
                    return null;
                }
            }
            return "REDIRECT";
        }
        if (r.status != 200 || newFail) {
            return null;
        }
        boolean baseHas = Form.hasPassword(base.body);
        boolean nowHas = Form.hasPassword(r.body);
        if (!nowHas) {
            if (!baseHas) {
                return null;
            }
            return (r.setCookie
                    || Math.abs(r.body.length() - base.body.length()) > Math.max(300, base.body.length() / 2))
                    ? "NOPW" : null;
        }
        return null;
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase();
    }

    private static String empty(String s) {
        return s == null || s.isEmpty() ? "(空)" : s;
    }

    private static String junk() {
        return "na" + Long.toHexString(System.nanoTime());
    }

    static String clip(String s, int n) {
        if (s == null) {
            return "";
        }
        String one = s.replaceAll("\\s+", " ").trim();
        return one.length() <= n ? one : one.substring(0, n) + "…";
    }
}
