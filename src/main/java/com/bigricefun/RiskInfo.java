package com.bigricefun;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** 一个 Web 服务上的全部风险。 */
final class RiskInfo {
    final String address;
    final List<RiskItem> items = new ArrayList<RiskItem>();

    RiskInfo(String address) {
        this.address = address;
    }

    void add(RiskItem it) {
        items.add(it);
    }

    private List<RiskItem> sorted() {
        List<RiskItem> s = new ArrayList<RiskItem>(items);
        Collections.sort(s, (a, b) -> RiskItem.rank(a.severity) - RiskItem.rank(b.severity));
        return s;
    }

    /** 「风险」列的一行文字。 */
    String summary() {
        StringBuilder b = new StringBuilder();
        for (RiskItem it : sorted()) {
            if (b.length() > 0) {
                b.append('；');
            }
            b.append(it.label());
        }
        return b.toString();
    }

    /** 追加到「响应」列末尾的完整证据。 */
    String detail() {
        StringBuilder b = new StringBuilder();
        for (RiskItem it : sorted()) {
            if (b.length() > 0) {
                b.append('\n');
            }
            b.append(it.detail());
        }
        return b.toString();
    }
}
