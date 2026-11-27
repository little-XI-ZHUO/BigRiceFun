package com.bigricefun;

import javafx.application.Platform;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;

/**
 * 状态栏进度。两个阶段（有重叠，Web 检测在扫描出结果时就开始）：
 *   扫描阶段  已完成扫描任务 / 总扫描任务      —— 总数来自输入（目标数 × 端口数）
 *   检测阶段  已完成 Web 检测 / 入队的 Web 检测
 * 文字和进度条都是独立控件：原程序会不停把状态 Label 覆写成 ip:port，进度不能写在那里。
 */
final class Progress {
    private final Label text = new Label();
    private final ProgressBar bar = new ProgressBar(0);
    private volatile long scanTotal = -1;
    private volatile long startedAt;

    Progress() {
        bar.setPrefWidth(190);
        bar.setPrefHeight(10);
        bar.setMinWidth(110);
        bar.setMaxHeight(10);
        bar.setStyle("-fx-accent: #e8734a;"); // 品牌橙
        text.setStyle("-fx-font-size: 12; -fx-text-fill: #555;");
    }

    Label text() {
        return text;
    }

    ProgressBar bar() {
        return bar;
    }

    /** 开始新一轮：记录起始时间，扫描总数由 setScanTotal 给。 */
    void begin() {
        startedAt = System.currentTimeMillis();
        scanTotal = -1;
        show("", 0);
    }

    /** 扫描任务总数。ip:port 模式 = 行数；IP×端口模式 = 目标数 × 端口数。 */
    void setScanTotal(long n) {
        scanTotal = n;
    }

    long scanTotal() {
        return scanTotal;
    }

    long startedAt() {
        return startedAt;
    }

    /**
     * 更新文字和进度条（内部切到 FX 线程）。frac < 0 表示总数未知，显示流动条；
     * frac == -2 表示不动进度条（停止时保留现场）。
     */
    void show(final String msg, final double frac) {
        if (Platform.isFxApplicationThread()) {
            text.setText(msg);
            if (frac != -2) {
                bar.setProgress(frac < 0 ? -1 : (frac > 1 ? 1 : frac));
            }
        } else {
            Platform.runLater(() -> show(msg, frac));
        }
    }

    static String elapsed(long ms) {
        long s = ms / 1000;
        return s < 60 ? String.format("00:%02d", s) : String.format("%02d:%02d", s / 60, s % 60);
    }
}
