package com.bigricefun;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 内置规则：未授权特征、登录入口、字典。都是静态表，改这里就改行为。
 * jar 同目录放一个 BigRiceFun-dict.txt（每行 user:pass，可用 max=N 调尝试上限）可覆盖通用字典。
 */
final class Rules {
    private Rules() {}

    /**
     * 通用字典最多试几组。通用口令会打到可能接了域账号的登录口，默认 8 组偏保守；
     * jar 旁的 BigRiceFun-dict.txt 里写 max=N 可放开。产品专属默认口令不占这个额度。
     */
    static final int MAX_GENERIC_DEFAULT = 8;
    static int maxGeneric = MAX_GENERIC_DEFAULT;

    /** 登录口触发锁定保护的特征（出现即停手）。英文一律小写。 */
    static final String[] LOCK_KW = {"账号已锁定", "账户已锁定", "已被锁定", "已锁定", "账号被锁", "账户锁定",
            "account is locked", "account locked", "account has been locked", "lockout", "too many attempts",
            "尝试次数过多", "账号已被禁用", "账户已禁用"};

    /** 登录失败的特征（相对基线新出现的才算）。 */
    static final String[] FAIL_KW = {"密码错误", "口令错误", "用户名或密码", "帐号或密码", "账号或密码", "账户或密码",
            "账号和密码", "用户名或口令", "密码不正确", "口令不正确", "用户名不存在", "账号不存在", "帐号不存在",
            "登录失败", "登陆失败", "认证失败", "验证失败", "校验失败", "名或密码错误",
            "invalid password", "invalid username", "invalid credentials", "invalid user", "incorrect password",
            "incorrect login", "authentication failed", "login failed", "logon failure", "bad password",
            "bad credentials", "wrong password", "wrong username", "password incorrect", "access denied",
            "authentication error", "login error", "invalid login",
            // JSON 接口的失败标志
            "\"success\":false", "\"success\": false", "\"result\":\"fail\"", "\"result\": \"fail\"",
            "\"result\":\"error\"", "\"result\": \"error\"", "\"status\":\"error\"", "\"status\": \"error\""};

    /** 登录成功页常见特征（相对基线新出现的才算）。 */
    static final String[] SUCCESS_KW = {"退出登录", "注销登录", "退出系统", "欢迎您", "欢迎回来", "welcome back",
            "logout", "sign out", "个人中心", "修改密码", "修改口令", "change password", "我的账户",
            "dashboard", "待办事项", "worklist",
            // JSON 接口的成功标志（语义明确、失败响应里不会出现的）
            "\"success\":true", "\"success\": true", "\"result\":\"success\"", "\"result\": \"success\"",
            "\"result\":\"ok\"", "\"result\": \"ok\"", "\"status\":\"ok\"", "\"status\": \"ok\""};

    /** 跳转目标含这些词，说明还停在登录流程里。 */
    static final String[] LOGINISH = {"login", "signin", "sign-in", "error", "fail", "denied", "logout"};

    /** 通用弱口令，按常见程度排序，靠前的先试。 */
    static String[][] GENERIC_PAIRS = pairs("admin:admin", "admin:", "admin:123456", "admin:admin123",
            "admin:password", "admin:12345678", "admin:admin888", "root:root", "test:test", "guest:guest",
            "user:user", "system:system", "manager:manager", "admin:111111", "admin:000000");

    /** 只有密码框的登录（用户名写死在设备里）。 */
    static final String[][] PASSWORD_ONLY = pairs("admin:", "admin:admin", "admin:123456", "admin:password",
            "admin:1234", "admin:12345", "admin:12345678", "admin:666666", "admin:888888", "admin:admin123");

    /** 页面出现关键字 -> 该产品常见的默认口令，排在通用字典前面。key 必须小写。 */
    static final Map<String, String[][]> PRODUCT_PAIRS = new LinkedHashMap<String, String[][]>();

    private static void product(String key, String... creds) {
        String[][] arr = pairs(creds);
        String[][] old = PRODUCT_PAIRS.get(key);
        if (old != null) {
            String[][] both = Arrays.copyOf(old, old.length + arr.length);
            System.arraycopy(arr, 0, both, old.length, arr.length);
            arr = both;
        }
        PRODUCT_PAIRS.put(key, arr);
    }

    static {
        product("nacos", "nacos:nacos", "nacos:nacos123");
        product("xxl-job", "admin:123456");
        product("weblogic", "weblogic:weblogic", "weblogic:welcome1", "weblogic:weblogic123", "weblogic:Oracle@123");
        product("jenkins", "admin:admin", "admin:password", "jenkins:jenkins", "admin:jenkins", "admin:123456");
        product("druid", "admin:admin", "druid:druid", "admin:123456", "admin:password", "root:root", "kafka:kafka");
        product("zabbix", "Admin:zabbix", "admin:zabbix");
        product("grafana", "admin:admin", "admin:admin123", "admin:password", "grafana:grafana");
        product("harbor", "admin:Harbor12345");
        product("gitlab", "root:12345678", "root:password", "root:admin");
        product("nexus", "admin:admin123");
        product("phpmyadmin", "root:", "root:root", "root:123456", "root:password", "mysql:mysql", "admin:admin");
        product("sonar", "admin:admin");
        product("kibana", "elastic:elastic", "kibana:kibana");
        product("solr", "admin:admin", "solr:SolrRocks");
        for (String k : new String[]{"若依", "ruoyi"}) {
            product(k, "admin:admin123");
        }
        for (String k : new String[]{"致远", "seeyon"}) {
            product(k, "system:system", "system:123456");
        }
        for (String k : new String[]{"泛微", "ecology"}) {
            product(k, "sysadmin:1", "sysadmin:sysadmin");
        }
        for (String k : new String[]{"用友", "yonyou"}) {
            product(k, "admin:admin", "admin:123456");
        }
        for (String k : new String[]{"金蝶", "kingdee"}) {
            product(k, "administrator:888888", "admin:admin");
        }
        for (String k : new String[]{"通达", "tongda"}) {
            product(k, "admin:", "admin:admin");
        }
        String[] cam = {"hikvision", "海康", "dahua", "大华", "nvr", "dvr", "ipc", "摄像头", "门禁", "摄像机"};
        for (String k : cam) {
            product(k, "admin:admin", "admin:12345", "admin:888888", "admin:88888", "admin:123456",
                    "888888:888888", "admin:666666");
        }
        String[] printer = {"printer", "打印机", "laserjet", "canon", "ricoh", "kyocera", "konica", "epson",
                "xerox", "brother", "sharp", "fuji xerox"};
        for (String k : printer) {
            product(k, "admin:", "admin:admin", "admin:12345678", "admin:password", "admin:1111", "admin:admin123");
        }
        String[] netdev = {"routeros", "mikrotik", "交换机", "路由器", "防火墙", "firewall", "fortigate", "sangfor",
                "深信服", "hillstone", "山石", "天融信", "topsec", "启明星辰", "venustech", "netgear", "tp-link",
                "tplink", "asus", "ubnt", "unifi", "h3c", "huawei", "华为", "ruijie", "锐捷", "juniper",
                "paloalto", "sophos", "zyxel", "dlink", "d-link", "腾达", "tenda", "mercury", "中兴", "zte",
                "烽火", "fiberhome", "爱快", "ikuai", "飞鱼星", "sundray", "信锐", "wzgsm"};
        for (String k : netdev) {
            product(k, "admin:admin", "admin:", "admin:123456", "admin:password", "admin:1234", "admin:12345",
                    "admin:admin123", "admin:666666", "admin:888888", "admin@huawei.com:admin@huawei.com",
                    "admin:Admin@123", "guest:guest", "user:user", "cisco:cisco", "support:support");
        }
    }

    /** 通用登录入口路径。 */
    static final String[] LOGIN_PATHS = {"/login", "/login.html", "/login.htm", "/login.php", "/login.jsp",
            "/admin", "/admin/login", "/manager/login", "/user/login",
            "/sys/login", "/system/login", "/jenkins/login", "/nacos/", "/xxl-job-admin/toLogin",
            "/druid/login.html", "/phpmyadmin/", "/zabbix/", "/console/login/LoginForm.jsp", "/manage",
            "/manager", "/index/login", "/api/login", "/member/login", "/login.aspx", "/login.asp",
            "/admin.aspx", "/admin.asp", "/admin/login.jsp",
            // 嵌入式设备（摄像头、NVR、门禁、路由器、打印机）
            "/index.html", "/index.htm", "/web/login.html", "/web/login.htm", "/doc/login.html",
            "/cgi-bin/luci", "/cgi-bin/login.cgi", "/goform/login", "/system/login.htm",
            "/portal/login.html", "/admin/login.html", "/admin/login.htm", "/user/login.html",
            "/Login", "/logon", "/home/login", "/auth/login", "/login/index", "/login/login"};

    /** 常见的 HTTP 认证入口（返回 401 就用对应字典试）。 */
    static final String[] AUTH_PATHS = {"/manager/html", "/admin", "/druid/index.html", "/api/overview",
            "/console", "/solr/", "/nacos/"};

    static List<String[]> pairsForAuth(String path) {
        String[] out;
        if (path.startsWith("/manager/html")) {
            out = new String[]{"tomcat:tomcat", "admin:admin", "tomcat:s3cret", "admin:password", "role1:role1",
                    "admin:tomcat", "tomcat:123456", "admin:123456", "manager:manager", "tomcat:admin"};
        } else if (path.startsWith("/admin")) {
            out = new String[]{"admin:admin", "admin:password", "admin:123456", "admin:"};
        } else if (path.startsWith("/druid")) {
            out = new String[]{"admin:admin", "druid:druid", "kafka:kafka", "admin:123456", "admin:password",
                    "root:root", "admin:druid"};
        } else if (path.startsWith("/api/overview")) {
            out = new String[]{"guest:guest", "rabbitmq:rabbitmq", "admin:admin"};
        } else if (path.startsWith("/nacos")) {
            out = new String[]{"nacos:nacos", "nacos:nacos123"};
        } else {
            out = new String[]{"admin:admin", "admin:", "admin:123456", "admin:password", "admin:12345",
                    "admin:1234", "admin:888888", "admin:admin123", "guest:guest", "user:user", "root:root",
                    "cisco:cisco", "huawei:huawei", "ubnt:ubnt", "support:support",
                    "administrator:administrator", "666666:666666", "888888:888888", "admin:666666", "admin:1111"};
        }
        List<String[]> list = new ArrayList<String[]>();
        for (String c : out) {
            addUnique(list, split(c));
        }
        return cap(list, 12);
    }

    /** 基础设施类控制台的弱口令按严重算。 */
    static boolean infra(String path) {
        return path.startsWith("/manager/html") || path.startsWith("/admin") || path.startsWith("/druid")
                || path.startsWith("/api/overview") || path.startsWith("/nacos") || path.startsWith("/solr")
                || path.startsWith("/console");
    }

    static List<String[]> pairsForForm(String page, boolean passwordOnly) {
        String low = page.toLowerCase();
        List<String[]> out = new ArrayList<String[]>();
        for (Map.Entry<String, String[][]> e : PRODUCT_PAIRS.entrySet()) {
            if (low.contains(e.getKey())) {
                for (String[] p : e.getValue()) {
                    addUnique(out, p);
                }
            }
        }
        String[][] generic = passwordOnly ? PASSWORD_ONLY : GENERIC_PAIRS;
        int used = 0;
        for (String[] p : generic) {
            if (used >= maxGeneric) {
                break;
            }
            if (addUnique(out, p)) {
                used++;
            }
        }
        return out;
    }

    /** 页面命中的第一个产品关键字，没有返回 null。 */
    static String product(String page) {
        String low = page.toLowerCase();
        for (String k : PRODUCT_PAIRS.keySet()) {
            if (low.contains(k)) {
                return k;
            }
        }
        return null;
    }

    static void loadDict(File dir) {
        File f = new File(dir, "BigRiceFun-dict.txt");
        if (!f.isFile()) {
            return;
        }
        try {
            List<String[]> list = new ArrayList<String[]>();
            for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (line.startsWith("max=")) {
                    maxGeneric = Math.max(1, Math.min(500, Integer.parseInt(line.substring(4).trim())));
                    continue;
                }
                int i = line.indexOf(':');
                if (i > 0) {
                    addUnique(list, new String[]{line.substring(0, i), line.substring(i + 1)});
                }
            }
            if (!list.isEmpty()) {
                GENERIC_PAIRS = list.toArray(newStringArray(list.size()));
            }
        } catch (Exception ignore) {
            // 字典文件有问题就用内置的
        }
    }

    private static String[][] newStringArray(int n) {
        return new String[n][];
    }

    /** 没重复才加入；返回是否真的加了。 */
    private static boolean addUnique(List<String[]> list, String[] p) {
        for (String[] e : list) {
            if (e[0].equals(p[0]) && e[1].equals(p[1])) {
                return false;
            }
        }
        list.add(p);
        return true;
    }

    private static List<String[]> cap(List<String[]> list, int max) {
        return list.size() > max ? new ArrayList<String[]>(list.subList(0, max)) : list;
    }

    private static String[] split(String cred) {
        int i = cred.indexOf(':');
        return new String[]{cred.substring(0, i), cred.substring(i + 1)};
    }

    private static String[][] pairs(String... creds) {
        String[][] out = new String[creds.length][];
        for (int i = 0; i < creds.length; i++) {
            out[i] = split(creds[i]);
        }
        return out;
    }

    // ---------------- 未授权访问特征 ----------------

    /** 一条特征：路径 + 命中关键字。kw 默认全部命中才算（any=true 任一命中即可）。 */
    static final class Rule {
        final String path, sev, title, fix;
        final String[] kw;
        final boolean head, any, ignoreCase;
        final long minLen;

        Rule(String path, String[] kw, String sev, String title, String fix) {
            this(path, kw, false, false, true, 0, sev, title, fix);
        }

        Rule(String path, String[] kw, boolean any, String sev, String title, String fix) {
            this(path, kw, false, any, true, 0, sev, title, fix);
        }

        /** head=true：只发 HEAD，200 且返回体够大或为二进制流即命中。 */
        Rule(String path, long minLen, String sev, String title, String fix) {
            this(path, new String[0], true, false, true, minLen, sev, title, fix);
        }

        Rule(String path, String[] kw, boolean head, boolean any, boolean ignoreCase, long minLen,
             String sev, String title, String fix) {
            this.path = path;
            this.kw = kw;
            this.head = head;
            this.any = any;
            this.ignoreCase = ignoreCase;
            this.minLen = minLen;
            this.sev = sev;
            this.title = title;
            this.fix = fix;
        }

        boolean hit(Http.Resp r) {
            if (r == null || r.status != 200) {
                return false;
            }
            if (head) {
                return minLen <= 0 || r.contentLength >= minLen
                        || r.contentType.toLowerCase().contains("octet-stream");
            }
            String b = r.body == null ? "" : r.body;
            int n = 0;
            for (String k : kw) {
                boolean has = ignoreCase ? containsIgnoreCase(b, k) : b.contains(k);
                if (has && any) {
                    return true;
                }
                if (has) {
                    n++;
                }
            }
            return !any && n == kw.length;
        }

        /** 命中的关键字，写进证据。 */
        String matched(Http.Resp r) {
            String b = r == null || r.body == null ? "" : r.body;
            StringBuilder sb = new StringBuilder();
            for (String k : kw) {
                boolean has = ignoreCase ? containsIgnoreCase(b, k) : b.contains(k);
                if (has) {
                    if (sb.length() > 0) {
                        sb.append(", ");
                    }
                    sb.append(k);
                }
            }
            return sb.toString();
        }
    }

    static boolean containsIgnoreCase(String s, String k) {
        return s.regionMatches(true, 0, k, 0, k.length()) || containsLoose(s, k);
    }

    private static boolean containsLoose(String s, String k) {
        String ls = s.toLowerCase();
        return ls.contains(k.toLowerCase());
    }

    static final String A_ENV = "env/heapdump 等端点会泄露配置项和口令：management.endpoint.*.enabled 设为 false，或只对管理网段开放。";
    static final String A_API = "关闭生产环境的接口文档，或加访问控制。";
    static final String A_CONSOLE = "立即启用认证并修改默认口令，管理端只对管理网段开放。";
    static final String A_UNAUTH = "开启认证并限制来源网段；已暴露期间确认数据是否被读取或写入。";

    static final Rule[] UNAUTH = {
            new Rule("/actuator/env", new String[]{"propertySources"}, "严重", "Spring Actuator env 未授权", A_ENV),
            new Rule("/env", new String[]{"propertySources"}, "严重", "Spring env 端点未授权", A_ENV),
            new Rule("/actuator/heapdump", 4096L, "严重", "Actuator heapdump 未授权",
                    "堆转储可下载并从中提取口令：关闭该端点。"),
            new Rule("/actuator/jolokia", new String[]{"mbean"}, "高危", "Actuator Jolokia 未授权", A_ENV),
            new Rule("/jolokia/list", new String[]{"mbean"}, "高危", "Jolokia 未授权", A_ENV),
            new Rule("/actuator/mappings", new String[]{"contexts"}, "高危", "Actuator mappings 暴露", A_ENV),
            new Rule("/actuator/beans", new String[]{"contexts"}, "高危", "Actuator beans 暴露", A_ENV),
            new Rule("/actuator/gateway/routes", new String[]{"routes"}, "高危", "Gateway 路由信息泄露", A_ENV),
            new Rule("/actuator", new String[]{"_links"}, "低危", "Actuator 端点列表暴露", A_ENV),
            new Rule("/swagger-ui.html", new String[]{"swagger"}, "低危", "Swagger UI 未授权", A_API),
            new Rule("/swagger-ui/index.html", new String[]{"swagger"}, "低危", "Swagger UI 未授权", A_API),
            new Rule("/swagger-resources", new String[]{"swagger"}, "低危", "Swagger 资源接口未授权", A_API),
            new Rule("/v2/api-docs", new String[]{"\"swagger\"", "2.0"}, "中危", "API 文档泄露（v2）", A_API),
            new Rule("/v3/api-docs", new String[]{"\"openapi\""}, "中危", "API 文档泄露（v3）", A_API),
            new Rule("/doc.html", new String[]{"knife4j"}, "低危", "Knife4j 接口文档未授权", A_API),
            new Rule("/druid/index.html", new String[]{"sql.html"}, "高危", "Druid 监控未授权",
                    "开启 StatViewServlet 的 login-username/login-password，或限制来源网段。"),
            new Rule("/nacos/v1/auth/users?pageNo=1&pageSize=1", new String[]{"pageItems"}, "严重",
                    "Nacos 用户信息未授权", A_CONSOLE),
            new Rule("/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=1",
                    new String[]{"pageItems"}, "严重", "Nacos 配置信息未授权", A_CONSOLE),
            new Rule("/jenkins/script", new String[]{"println"}, "严重", "Jenkins 脚本控制台未授权", A_CONSOLE),
            new Rule("/script", new String[]{"println", "groovy"}, "严重", "Jenkins 脚本控制台未授权", A_CONSOLE),
            new Rule("/jenkins/computer/api/json?depth=1", new String[]{"busyExecutors"}, "高危",
                    "Jenkins 未授权", A_CONSOLE),
            new Rule("/computer/api/json?depth=1", new String[]{"busyExecutors"}, "高危", "Jenkins 未授权",
                    A_CONSOLE),
            new Rule("/manager/html", new String[]{"tomcat"}, "严重", "Tomcat Manager 未授权", A_CONSOLE),
            new Rule("/jmx-console/", new String[]{"jboss"}, "严重", "JBoss JMX 控制台未授权", A_CONSOLE),
            new Rule("/web-console/", new String[]{"jboss"}, "高危", "JBoss Web 控制台未授权", A_CONSOLE),
            new Rule("/admin/", new String[]{"activemq"}, "严重", "ActiveMQ 控制台未授权", A_CONSOLE),
            new Rule("/h2-console", new String[]{"h2 console"}, "高危", "H2 数据库控制台暴露", A_CONSOLE),
            new Rule("/api/org", new String[]{"\"name\"", "\"id\""}, "高危", "Grafana 未授权", A_UNAUTH),
            new Rule("/api/overview", new String[]{"rabbitmq_version"}, "高危", "RabbitMQ 管理台未授权", A_CONSOLE),
            new Rule("/containers/json?all=1", new String[]{"\"Names\""}, "严重", "Docker API 未授权",
                    "Docker API 等于宿主机 root 权限：绑定 127.0.0.1 并开启 TLS。"),
            new Rule("/version", new String[]{"\"ApiVersion\""}, false, true, false, 0, "严重", "Docker API 未授权",
                    "Docker API 等于宿主机 root 权限：绑定 127.0.0.1 并开启 TLS。"),
            new Rule("/pods", new String[]{"\"containers\""}, "严重", "Kubelet 未授权",
                    "关闭匿名访问或只对管理网段开放 10255。"),
            new Rule("/api/v1/namespaces/default/secrets", new String[]{"\"items\""}, "严重", "K8s Secrets 未授权",
                    "开启 API Server 认证授权。"),
            new Rule("/api", new String[]{"\"/api/v1\""}, "中危", "K8s API 未授权", "开启 API Server 认证授权。"),
            new Rule("/v1/catalog/services", new String[]{"\"consul\""}, "高危", "Consul 未授权", A_UNAUTH),
            new Rule("/v1/kv/?recurse", new String[]{"\"Key\""}, "严重", "Consul KV 未授权", A_UNAUTH),
            new Rule("/v2/keys", new String[]{"\"action\":\"get\""}, "高危", "etcd 未授权", A_UNAUTH),
            new Rule("/ws/v1/cluster/apps", new String[]{"\"apps\""}, "高危", "Hadoop Yarn 未授权", A_UNAUTH),
            new Rule("/webhdfs/v1/?op=LISTSTATUS", new String[]{"FileStatuses"}, "高危", "HDFS Web 未授权", A_UNAUTH),
            new Rule("/overview", new String[]{"taskmanagers"}, "高危", "Flink 未授权", A_UNAUTH),
            new Rule("/_cat/indices?v", new String[]{"health", "index"}, "高危", "Elasticsearch 未授权", A_UNAUTH),
            new Rule("/solr/admin/", new String[]{"solr"}, "高危", "Solr 管理页未授权", A_UNAUTH),
            new Rule("/api/v2.0/users", new String[]{"\"username\""}, "严重", "Harbor 用户信息未授权", A_CONSOLE),
            new Rule("/phpinfo.php", new String[]{"PHP Version"}, "中危", "phpinfo 信息泄露", "删除调试页面。"),
            new Rule("/info.php", new String[]{"PHP Version"}, "中危", "phpinfo 信息泄露", "删除调试页面。"),
            new Rule("/.git/HEAD", new String[]{"ref: refs/"}, "高危", ".git 目录泄露",
                    "禁止 Web 访问 .git；已泄露则视为源码外泄，轮换其中的口令。"),
            new Rule("/.svn/entries", new String[]{"kind="}, "高危", ".svn 目录泄露",
                    "禁止 Web 访问 .svn；已泄露则轮换其中的口令。"),
            new Rule("/WEB-INF/web.xml", new String[]{"<web-app"}, "高危", "WEB-INF 配置文件泄露",
                    "禁止访问 WEB-INF；检查其中数据源口令。"),
            new Rule("/.env", new String[]{"APP_KEY", "DB_PASSWORD", "DB_USERNAME"}, true, "严重",
                    ".env 配置文件泄露", "禁止访问点开头的文件；轮换其中的密钥和口令。"),
            new Rule("/metrics", new String[]{"# HELP"}, "低危", "监控指标暴露", "监控端点限制来源网段。"),
            new Rule("/debug/pprof/", new String[]{"pprof"}, "中危", "pprof 调试端点暴露", "生产环境关闭 pprof。"),
    };
}
