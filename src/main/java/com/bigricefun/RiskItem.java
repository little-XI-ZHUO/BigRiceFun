package com.bigricefun;

/** 一条风险。severity 用 严重/高危/中危/低危/信息。 */
final class RiskItem {
    static final String[] ORDER = {"严重", "高危", "中危", "低危", "信息"};

    final String severity, type, title, url, account, password, evidence, advice;

    RiskItem(String severity, String type, String title, String url, String account, String password,
             String evidence, String advice) {
        this.severity = severity;
        this.type = type;
        this.title = title;
        this.url = url;
        this.account = account == null ? "" : account;
        this.password = password == null ? "" : password;
        this.evidence = evidence == null ? "" : evidence;
        this.advice = advice == null ? "" : advice;
    }

    static int rank(String sev) {
        for (int i = 0; i < ORDER.length; i++) {
            if (ORDER[i].equals(sev)) {
                return i;
            }
        }
        return ORDER.length;
    }

    String label() {
        return "[" + severity + "] " + title;
    }

    String detail() {
        StringBuilder b = new StringBuilder();
        b.append(label()).append('\n');
        b.append("    入口: ").append(url).append('\n');
        if (!account.isEmpty() || !password.isEmpty()) {
            b.append("    账号口令: ").append(account).append(" / ").append(password.isEmpty() ? "(空)" : password).append('\n');
        }
        b.append("    证据: ").append(evidence).append('\n');
        b.append("    建议: ").append(advice);
        return b.toString();
    }
}
