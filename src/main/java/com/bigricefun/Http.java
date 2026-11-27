package com.bigricefun;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Web 检测用的 HTTP 客户端：信任所有证书、不自动跟随跳转（登录是否成功要看 302 本身）、
 * 自带凭据时自动应答 Basic / Digest 质询。全部用 jar 里已有的 httpclient 4.5.8，不引入新依赖。
 */
final class Http implements Closeable {
    static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
            + " Chrome/124.0.0.0 Safari/537.36";
    private static final int MAX_BODY = 256 * 1024;
    private static final Pattern CHARSET = Pattern.compile("(?i)charset=[\"']?([\\w-]+)");

    static final class Resp {
        int status; // 0 = 连接失败或超时
        String body = "";
        String location = "";
        String contentType = "";
        String wwwAuth = "";
        String server = "";
        String finalUrl = "";
        long contentLength = -1;
        boolean setCookie;
        final Map<String, String> headers = new LinkedHashMap<String, String>();
    }

    interface Creds {
        String user();

        String pass();
    }

    private final CloseableHttpClient client;

    Http(int timeoutMs) throws Exception {
        SSLContext ctx = SSLContexts.custom().loadTrustMaterial(TrustAllStrategy.INSTANCE).build();
        HostnameVerifier trust = (host, session) -> true;
        client = HttpClients.custom()
                .setSSLContext(ctx).setSSLHostnameVerifier(trust)
                .disableRedirectHandling().disableAutomaticRetries()
                .setMaxConnTotal(400).setMaxConnPerRoute(64)
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectTimeout(timeoutMs).setSocketTimeout(timeoutMs)
                        .setConnectionRequestTimeout(timeoutMs)
                        .setCookieSpec(CookieSpecs.STANDARD).build())
                .build();
    }

    /** 发一个请求。creds 不为空时，遇到 401 自动用这组凭据应答 Basic/Digest 质询。 */
    Resp send(String method, String url, List<NameValuePair> form, Creds creds, BasicCookieStore jar, String referer) {
        Resp r = new Resp();
        r.finalUrl = url;
        HttpRequestBase req;
        if ("POST".equals(method)) {
            req = new HttpPost(url);
        } else if ("HEAD".equals(method)) {
            req = new HttpHead(url);
        } else {
            req = new HttpGet(url);
        }
        try {
            req.setHeader("User-Agent", UA);
            req.setHeader("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8");
            req.setHeader("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.6");
            if (referer != null && !referer.isEmpty()) {
                req.setHeader("Referer", referer);
            }
            if (form != null) {
                ((HttpEntityEnclosingRequestBase) req).setEntity(new UrlEncodedFormEntity(form, "UTF-8"));
            }
            HttpClientContext cx = HttpClientContext.create();
            if (jar != null) {
                cx.setCookieStore(jar);
            }
            if (creds != null) {
                BasicCredentialsProvider p = new BasicCredentialsProvider();
                p.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(creds.user(), creds.pass()));
                cx.setCredentialsProvider(p);
            }
            CloseableHttpResponse resp = client.execute(req, cx);
            try {
                r.status = resp.getStatusLine().getStatusCode();
                for (Header h : resp.getAllHeaders()) {
                    String n = h.getName().toLowerCase();
                    String v = h.getValue();
                    if (n.equals("location")) {
                        r.location = v;
                    } else if (n.equals("www-authenticate")) {
                        r.wwwAuth = v;
                    } else if (n.equals("content-type")) {
                        r.contentType = v == null ? "" : v;
                    } else if (n.equals("server")) {
                        r.server = v == null ? "" : v;
                    }
                    if (n.equals("set-cookie")) {
                        r.setCookie = true;
                    }
                    r.headers.merge(n, v == null ? "" : v, (a, b) -> a + "\r\n" + b);
                }
                HttpEntity en = resp.getEntity();
                if (en != null) {
                    r.contentLength = en.getContentLength();
                    String ct = r.contentType.toLowerCase();
                    boolean textual = ct.contains("text") || ct.contains("json") || ct.contains("xml")
                            || ct.contains("javascript") || ct.contains("svg") || ct.isEmpty();
                    if (!"HEAD".equals(method) && textual) {
                        try (InputStream in = en.getContent()) {
                            r.body = decode(read(in, MAX_BODY), r.contentType);
                        }
                    }
                }
            } finally {
                resp.close();
            }
        } catch (IOException e) {
            r.status = 0;
        } finally {
            req.releaseConnection();
        }
        return r;
    }

    /** GET，手动跟随最多 4 次跳转。 */
    Resp get(String url, BasicCookieStore jar) {
        Resp r = send("GET", url, null, null, jar, null);
        String cur = url;
        int hops = 0;
        while (r.status >= 300 && r.status < 400 && !r.location.isEmpty() && hops < 4) {
            cur = resolve(cur, r.location);
            r = send("GET", cur, null, null, jar, null);
            hops++;
        }
        r.finalUrl = cur;
        return r;
    }

    static String resolve(String base, String loc) {
        try {
            return new URL(new URL(base), loc).toString();
        } catch (Exception e) {
            return loc;
        }
    }

    private static byte[] read(InputStream in, int max) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n, total = 0;
        while ((n = in.read(buf)) > 0) {
            int take = Math.min(n, max - total);
            bo.write(buf, 0, take);
            total += take;
            if (total >= max) {
                break;
            }
        }
        return bo.toByteArray();
    }

    /** 先按响应头里的字符集，其次 UTF-8，都不行再按 GBK。 */
    static String decode(byte[] raw, String contentType) {
        Matcher m = CHARSET.matcher(contentType == null ? "" : contentType);
        if (m.find()) {
            try {
                return Charset.forName(m.group(1)).newDecoder()
                        .onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE)
                        .decode(ByteBuffer.wrap(raw)).toString();
            } catch (Exception ignore) {
                // 字符集名不认识，走下面的兜底
            }
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            try {
                return Charset.forName("GBK").newDecoder()
                        .onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE)
                        .decode(ByteBuffer.wrap(raw)).toString();
            } catch (Exception e2) {
                return new String(raw, StandardCharsets.ISO_8859_1);
            }
        }
    }

    @Override
    public void close() throws IOException {
        client.close();
    }
}
