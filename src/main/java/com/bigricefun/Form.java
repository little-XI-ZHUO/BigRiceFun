package com.bigricefun;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/** 登录表单。用 jar 里自带的 jsoup 解析。 */
final class Form {
    static final Pattern PW = Pattern.compile("(?i)type\\s*=\\s*[\"']?password");
    private static final Pattern CAPTCHA_INPUT = Pattern.compile(
            "(?i)((captcha|verify|checkcode|validate|vcode|yzm|authcode|randcode|imgcode|verif[ya]code)[\\w]*)|code$");
    private static final Pattern CAPTCHA_IMG = Pattern.compile("(?i)(captcha|verify|vcode|validate|code|yzm)");
    private static final Pattern TOKEN = Pattern.compile(
            "(?i)(token|csrf|__RequestVerification|_csrf|execution|nonce|formkey|form_key|_stoken|__hash|_token|authenticity_token)");

    String action, pageUrl, userField, passField, title = "";
    String method = "POST";
    final Map<String, String> hidden = new LinkedHashMap<String, String>();
    boolean captcha, tokenRefresh;

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

    /** 取页面里第一个带密码框的 form；没有返回 null。 */
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
            for (Element in : fe.select("input")) {
                String tag = (in.attr("name") + " " + in.attr("id")).toLowerCase();
                if (CAPTCHA_INPUT.matcher(tag).find()) {
                    f.captcha = true;
                }
                if (in.attr("type").equalsIgnoreCase("hidden") && TOKEN.matcher(in.attr("name")).find()) {
                    f.tokenRefresh = true;
                }
            }
            for (Element img : fe.select("img")) {
                if (CAPTCHA_IMG.matcher(img.attr("src").toLowerCase()).find()) {
                    f.captcha = true;
                }
            }
            return f;
        }
        return null;
    }

    @Override
    public String toString() {
        return method + " " + action + " user=" + userField + " pass=" + passField + (captcha ? " [验证码]" : "");
    }
}
