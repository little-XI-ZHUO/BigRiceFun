package com.bigricefun;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 登录表单。用 jar 里自带的 jsoup 解析。 */
final class Form {
    static final Pattern PW = Pattern.compile("(?i)type\\s*=\\s*[\"']?password");
    private static final Pattern CAPTCHA_INPUT = Pattern.compile(
            "(?i)((captcha|verify|checkcode|validate|vcode|yzm|authcode|randcode|imgcode|verif[ya]code)[\\w]*)|code$");
    private static final Pattern CAPTCHA_IMG = Pattern.compile("(?i)(captcha|verify|vcode|validate|code|yzm)");
    private static final Pattern TOKEN = Pattern.compile(
            "(?i)(token|csrf|__RequestVerification|_csrf|execution|nonce|formkey|form_key|_stoken|__hash|_token|authenticity_token)");
    /** 页面里（含 JS）出现的提交地址：url:"/xxx"、action:"/xxx"、action='/xxx'、.post("/xxx")、.ajax({url:"/xxx" */
    private static final Pattern ACTION_IN_SCRIPT = Pattern.compile(
            "(?is)(?:url|action)\\s*[:=]\\s*[\"']([^\"'\\s>]{1,120})[\"']|(?:post|get|ajax)\\s*\\(\\s*[\"']([^\"'\\s)]{1,120})[\"']");
    private static final Pattern LOGIN_WORD = Pattern.compile("(?is)(登\\s*录|登\\s*陸|log\\s*in|log\\s*on|sign\\s*in)");
    private static final Pattern VALUE_ATTR = Pattern.compile("(?is)value\\s*=\\s*[\"']([^\"']*)[\"']");
    private static final Pattern NAME_ATTR = Pattern.compile("(?is)\\bname\\s*=\\s*[\"']([^\"']*)[\"']");
    private static final Pattern ID_ATTR = Pattern.compile("(?is)\\bid\\s*=\\s*[\"']([^\"']*)[\"']");
    private static final Pattern TYPE_ATTR = Pattern.compile("(?is)\\btype\\s*=\\s*[\"']?([\\w-]+)");
    private static final Pattern INPUT_TAG = Pattern.compile("(?is)<input\\b[^>]*>");
    /** 能当用户名框的 type：空、text、email、tel、number。 */
    private static final Pattern TEXTUAL = Pattern.compile("^(?i)(|text|email|tel|number)$");

    String action, pageUrl, userField, passField, title = "";
    String method = "POST";
    final Map<String, String> hidden = new LinkedHashMap<String, String>();
    boolean captcha, tokenRefresh;
    /** 页面没有 <form>，是靠 input + JS 提交的登录框（嵌入式设备、SPA 常见）。 */
    boolean virtual;
    /** 提交地址是从 JS 里抠出来的（而不是 form 的 action 属性）。 */
    boolean actionFromScript;

    static boolean hasPassword(String html) {
        return html != null && PW.matcher(html).find();
    }

    static String title(String html) {
        try {
            Document d = Jsoup.parse(html == null ? "" : html);
            return d.title() == null ? "" : d.title().trim();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 取页面里第一个带密码框的 form。没有 form 但页面像登录页时（密码框 + 用户名框 + 登录字样），
     * 用散落的 input 凑一个虚拟表单，提交地址从 JS 里抠。都没有返回 null。
     */
    static Form parse(String pageUrl, String html) {
        Form f = new Form();
        f.pageUrl = pageUrl;
        Document doc;
        try {
            doc = Jsoup.parse(html == null ? "" : html, pageUrl);
        } catch (Exception e) {
            return null;
        }
        f.title = doc.title() == null ? "" : doc.title().trim();
        for (Element fe : doc.select("form")) {
            f.userField = null;
            f.passField = null;
            f.hidden.clear();
            for (Element in : fe.select("input")) {
                String name = in.attr("name");
                if (name.isEmpty()) {
                    continue;
                }
                String type = in.attr("type").toLowerCase();
                if (type.isEmpty() || type.equals("text") || type.equals("email") || type.equals("tel")
                        || type.equals("number")) {
                    if (f.userField == null) {
                        f.userField = name;
                    }
                } else if (type.equals("password")) {
                    f.passField = name;
                } else if (type.equals("hidden")) {
                    f.hidden.put(name, in.attr("value"));
                }
            }
            if (f.passField == null) {
                continue;
            }
            f.action = fe.absUrl("action");
            if (f.action.isEmpty()) {
                f.action = pageUrl;
            }
            String m = fe.attr("method").trim().toUpperCase();
            f.method = m.equals("GET") ? "GET" : "POST";
            markCaptchaAndToken(f, fe.select("input"), fe.select("img"));
            return f;
        }
        Form v = virtualForm(pageUrl, html, doc);
        return v;
    }

    private static void markCaptchaAndToken(Form f, org.jsoup.select.Elements inputs, org.jsoup.select.Elements imgs) {
        for (Element in : inputs) {
            String tag = (in.attr("name") + " " + in.attr("id")).toLowerCase();
            if (CAPTCHA_INPUT.matcher(tag).find()) {
                f.captcha = true;
            }
            if (in.attr("type").equalsIgnoreCase("hidden") && TOKEN.matcher(in.attr("name")).find()) {
                f.tokenRefresh = true;
            }
        }
        for (Element img : imgs) {
            if (CAPTCHA_IMG.matcher(img.attr("src").toLowerCase()).find()) {
                f.captcha = true;
            }
        }
    }

    /**
     * 没有 <form> 的登录框：嵌入式设备、SPA 常这么写——两个 input 加一个按钮，JS 发请求。
     * 这里不靠 DOM 结构，直接扫所有 <input> 标签找用户名/密码字段，action 从 JS 里抠。
     */
    private static Form virtualForm(String pageUrl, String html, Document doc) {
        if (html == null || !PW.matcher(html).find()) {
            return null;
        }
        // 必须像登录页：有密码框，且有「登录」字样或登录类 id/class
        String low = html.toLowerCase();
        boolean looksLogin = LOGIN_WORD.matcher(html).find()
                || low.contains("id=\"login\"") || low.contains("class=\"login") || low.contains("id=\"passwd\"")
                || low.contains("name=\"password\"") || low.contains("name=\"pwd\"") || low.contains("name=\"pass\"")
                || low.contains("name=\"username\"") || low.contains("name=\"user\"") || low.contains("name=\"uname\"");
        if (!looksLogin) {
            return null;
        }

        Form f = new Form();
        f.pageUrl = pageUrl;
        f.virtual = true;
        f.title = doc.title() == null ? "" : doc.title().trim();

        // 用户名框：按 name/id 语义找，找不到就取密码框前面最近的 text 框
        Matcher m = INPUT_TAG.matcher(html);
        java.util.List<String[]> inputs = new java.util.ArrayList<String[]>();
        int pwIndex = -1;
        while (m.find()) {
            String tag = m.group();
            String type = attr(tag, TYPE_ATTR, "text").toLowerCase();
            String name = attr(tag, NAME_ATTR, "");
            if (name.isEmpty()) {
                name = attr(tag, ID_ATTR, ""); // 没有 name 就用 id，很多设备 JS 就是按 id 取值
            }
            inputs.add(new String[]{type, name, tag});
            if (type.equals("password") && pwIndex < 0 && !name.isEmpty()) {
                pwIndex = inputs.size() - 1;
            }
        }
        if (pwIndex < 0) {
            return null;
        }
        f.passField = inputs.get(pwIndex)[1];
        // 用户名：先看密码框之前的 text/email/tel 框，再看全页
        for (int i = pwIndex - 1; i >= 0 && f.userField == null; i--) {
            String[] in = inputs.get(i);
            if (!in[1].isEmpty() && TEXTUAL.matcher(in[0]).matches()) {
                f.userField = in[1];
            }
        }
        if (f.userField == null) {
            for (String[] in : inputs) {
                if (!in[1].isEmpty() && !in[0].equals("password") && !in[0].equals("hidden")
                        && !in[0].equals("submit") && !in[0].equals("button")) {
                    f.userField = in[1];
                    break;
                }
            }
        }
        // 其它 hidden 一起带上（csrf 之类）
        for (String[] in : inputs) {
            if (in[0].equals("hidden") && !in[1].isEmpty()) {
                f.hidden.put(in[1], attr(in[2], VALUE_ATTR, ""));
            }
        }
        // 验证码：input 的 name/id 或全页 img 的 src 带 captcha 字样
        for (String[] in : inputs) {
            String tag = in[1].toLowerCase() + " " + attr(in[2], ID_ATTR, "").toLowerCase();
            if (CAPTCHA_INPUT.matcher(tag).find()) {
                f.captcha = true;
            }
        }
        for (Element img : doc.select("img")) {
            if (CAPTCHA_IMG.matcher(img.attr("src").toLowerCase()).find()) {
                f.captcha = true;
            }
        }
        // 提交地址：JS 里的 url:"..." / action:"..." / .post("...")；抠不到就提交到当前页
        Matcher a = ACTION_IN_SCRIPT.matcher(html);
        while (a.find()) {
            String cand = a.group(1) != null ? a.group(1) : a.group(2);
            if (cand == null || cand.isEmpty() || cand.startsWith("#") || cand.startsWith("data:")
                    || cand.startsWith("javascript:") || cand.endsWith(".js") || cand.endsWith(".css")
                    || cand.endsWith(".png") || cand.endsWith(".jpg") || cand.endsWith(".gif")) {
                continue;
            }
            cand = cand.replaceAll("\\\\/", "/");
            // 优先带 login 字样的地址，其次 /api/ 类；明显的列表/查询接口跳过
            String lc = cand.toLowerCase();
            if (lc.contains("list") || lc.contains("query") || lc.contains("search") || lc.contains("config")
                    || lc.contains("status") || lc.contains("version") || lc.contains("info")) {
                continue;
            }
            f.action = Http.resolve(pageUrl, cand);
            f.actionFromScript = true;
            if (lc.contains("login") || lc.contains("auth") || lc.contains("session")) {
                break; // 带 login 字样的最像，找到就用
            }
        }
        if (f.action == null || f.action.isEmpty()) {
            f.action = pageUrl;
        }
        return f;
    }

    private static String attr(String tag, Pattern p, String def) {
        Matcher m = p.matcher(tag);
        return m.find() ? m.group(1) : def;
    }

    @Override
    public String toString() {
        return method + " " + action + " user=" + userField + " pass=" + passField
                + (virtual ? " [虚拟表单]" : "") + (actionFromScript ? " [地址取自JS]" : "")
                + (captcha ? " [验证码]" : "");
    }
}
