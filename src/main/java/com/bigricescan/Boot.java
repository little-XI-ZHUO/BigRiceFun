package com.bigricescan;

import com.webfinder.portscan.FXMLDocumentController;
import com.webfinder.portscan.model.Row;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.ListChangeListener;
import javafx.event.ActionEvent;
import javafx.geometry.Insets;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.Tooltip;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Web 检测：加「风险」列、两个开关、导出按钮，
 * 并接管状态栏——扫描任务和 Web 检测全部结束才显示「已完成」。
 */
final class Boot {
    private static final String DETAIL_MARK = "===== 风险详情 =====";
    private static final String P_SCAN = "扫描中…";
    private static final String P_WEB = "Web 检测中…";
    private static final String P_SETTLE = "收尾中…";
    private static final String STOPPED = "已停止";
    /** 程序发完完成信号后，至少安静这么久且没有新行进来才收尾。 */
    private static final long SETTLE_MS = 1500;

    private Stage stage;
    private Parent root;
    private TableView<Row> table;
    private Label status;
    private ExecutorService scanPool;
    private long nextPoolLookup;
    private CheckBox chkBrute, chkUnauth;

    private final Map<Row, StringProperty> riskOf = Collections.synchronizedMap(new WeakHashMap<Row, StringProperty>());
    private final Map<String, RiskInfo> byAddress = new ConcurrentHashMap<String, RiskInfo>();
    private final Set<String> queued = ConcurrentHashMap.newKeySet();
    private final List<RiskInfo> found = Collections.synchronizedList(new ArrayList<RiskInfo>());
    private final ThreadPoolExecutor audit = new ThreadPoolExecutor(12, 12, 60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<Runnable>(), new ThreadFactory() {
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "web-risk-audit");
                    t.setDaemon(true);
                    t.setPriority(Thread.MIN_PRIORITY + 1);
                    return t;
                }
            });

    private volatile boolean appDone, finalized, stopped;
    private volatile long lastActivity;
    private int webTargets;

    // ---- 进度 ----
    private final Progress progress = new Progress();
    /** 本轮扫描开始时线程池的已完成任务数（池是复用的，要减基线）。 */
    private long scanBaseline = -1;
    /** 已经算过总数的扫描任务数（taskList 是累加的，只算新增的）。 */
    private int seenTasks;
    /** 本轮已完成的 Web 检测数。 */
    private volatile long auditDone;
    /** 缓存的控制器实例（FXML 事件处理器里挖出来的）。 */
    private Object controller;

    static void install(Stage stage) {
        new Boot().go(stage);
    }

    @SuppressWarnings("unchecked")
    private void go(Stage stage) {
        this.stage = stage;
        Parent root = stage.getScene().getRoot();
        this.root = root;
        table = (TableView<Row>) root.lookup("#id_tableview");
        status = (Label) root.lookup("#id_status");
        try {
            Rules.loadDict(new File(com.webfinder.portscan.Utils.JarUtils.getJarDir()));
        } catch (Exception ignore) {
            // 没有外置字典就用内置的
        }

        // 「风险」列：放在地址后面，文字按级别着色
        TableColumn<Row, String> col = new TableColumn<Row, String>("风险");
        col.setCellValueFactory(cd -> riskProperty(cd.getValue()));
        col.setCellFactory(c -> new TableCell<Row, String>() {
            @Override
            protected void updateItem(String v, boolean empty) {
                super.updateItem(v, empty);
                if (empty || v == null || v.isEmpty()) {
                    setText(null);
                    setTooltip(null);
                    setTextFill(Color.BLACK);
                    setFont(Font.getDefault());
                    return;
                }
                setText(v);
                setTooltip(new Tooltip(v));
                setFont(Font.font("System", FontWeight.BOLD, 12));
                setTextFill(v.startsWith("[严重]") ? Color.rgb(160, 14, 38)
                        : v.startsWith("[高危]") ? Color.rgb(193, 37, 47)
                        : v.startsWith("[中危]") ? Color.rgb(176, 122, 0)
                        : Color.rgb(30, 90, 160));
            }
        });
        col.setMinWidth(110);
        col.setPrefWidth(210);
        table.getColumns().add(1, col);

        // 多了一列后各列按比例分宽度，给关键列定个合理比例，免得最后一列被挤没
        tune(table, "地址", 150, 180);
        tune(table, "Shiro", 44, 48);
        tune(table, "SSL", 44, 48);
        tune(table, "服务器", 56, 70);
        tune(table, "标题", 56, 70);
        tune(table, "状态码", 56, 62);
        tune(table, "ContentLength", 60, 70);
        tune(table, "响应", 62, 70);
        tune(table, "真实IP", 76, 90);

        // 「响应」列带上风险详情后行数很多，列又窄，会把每行撑得很高。
        // 改成只显示第一行，鼠标悬停看前 2000 字，点行在右下角看完整内容。
        List<TableColumn<Row, ?>> cols = new ArrayList<TableColumn<Row, ?>>(table.getColumns());
        for (TableColumn<Row, ?> c : cols) {
            if (!"响应".equals(c.getText())) {
                continue;
            }
            @SuppressWarnings("unchecked")
            TableColumn<Row, String> resp = (TableColumn<Row, String>) c;
            resp.setCellFactory(tc -> new TableCell<Row, String>() {
                @Override
                protected void updateItem(String v, boolean empty) {
                    super.updateItem(v, empty);
                    if (empty || v == null) {
                        setText(null);
                        setTooltip(null);
                        return;
                    }
                    setText(v.split("\n")[0]);
                    setTooltip(new Tooltip(v.length() > 2000 ? v.substring(0, 2000) + "…" : v));
                }
            });
        }

        // 表格每来一行新结果就排一个检测
        table.getItems().addListener((ListChangeListener<Row>) ch -> {
            while (ch.next()) {
                if (ch.wasAdded()) {
                    for (Row r : ch.getAddedSubList()) {
                        onRow(r);
                    }
                }
            }
        });

        // 工具栏：最左边放一个小 logo；「自动去除空节点」后面加两个开关和导出
        CheckBox auto = (CheckBox) root.lookup("#id_autodeleteempty");
        if (auto != null && auto.getParent() instanceof HBox) {
            HBox bar = (HBox) auto.getParent();
            ImageView logo = new ImageView(WebApp.icon(32, 18));
            HBox.setMargin(logo, new Insets(2, 6, 2, 2));
            bar.getChildren().add(0, logo);
            int at = bar.getChildren().indexOf(auto) + 1;
            chkBrute = new CheckBox("Web弱口令");
            chkBrute.setSelected(true);
            chkUnauth = new CheckBox("未授权检测");
            chkUnauth.setSelected(true);
            Button export = new Button("导出风险");
            export.addEventHandler(ActionEvent.ACTION, e -> exportCsv());
            bar.getChildren().add(at, export);
            bar.getChildren().add(at, chkUnauth);
            bar.getChildren().add(at, chkBrute);
        }

        // 状态栏：左边放进度文字和细进度条。原程序会不停把状态 Label 覆写成 ip:port，
        // 进度必须放在独立控件里才不会被冲掉
        if (status.getParent() instanceof HBox) {
            HBox bottom = (HBox) status.getParent();
            bottom.getChildren().add(0, progress.bar());
            bottom.getChildren().add(0, progress.text());
        }

        // 状态栏：程序自己写 complete 时如果还有活没干完，立刻改回进行中
        status.textProperty().addListener((obs, old, val) -> onStatus(val));
        ScheduledExecutorService mono = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "web-risk-status");
            t.setDaemon(true);
            return t;
        });
        mono.scheduleWithFixedDelay(this::tick, 200, 250, TimeUnit.MILLISECONDS);
    }

    // ---------------- 状态栏 ----------------

    private void onStatus(String val) {
        if (val == null) {
            return;
        }
        if ("complete".equals(val)) {
            // 程序自己的完成条件只看任务计数和队列，漏了两样：正在跑的任务，
            // 以及它们跑完后才通过 Platform.runLater 进表格的行。所以这里不能直接收尾，
            // 要等"安静一段时间且没有新行进来"才算真完成（见 tick）。
            appDone = true;
            lastActivity = System.currentTimeMillis();
            if (!stopped) {
                status.setText(busy() ? progress() : P_SETTLE);
            }
        } else if ("stopped".equals(val)) {
            stopped = true;
            appDone = false;
            audit.getQueue().clear();
            status.setText(STOPPED);
            progress.show("已停止，用时 " + Progress.elapsed(System.currentTimeMillis() - progress.startedAt()), -2);
        } else if (STOPPED.equals(val)) {
            stopped = true;
            appDone = false;
            audit.getQueue().clear();
        } else if ("stopping...".equals(val)) {
            stopped = true;
            status.setText("停止中…");
        } else if ("scanning...".equals(val)) {
            stopped = false;
            finalized = false;
            appDone = false;
            progress.begin();
            auditDone = 0;
            webTargets = 0;
            ThreadPoolExecutor p = pool();
            scanBaseline = p != null ? p.getCompletedTaskCount() : -1;
            discoverScanTotal();
        }
    }

    private void tick() {
        // 进度条随时更新：扫描一开始就要能看到进度，不能等完成信号
        updateProgress();
        if (finalized || stopped || !appDone) {
            return;
        }
        final boolean idle = !busy() && System.currentTimeMillis() - lastActivity >= settleMs();
        Platform.runLater(() -> {
            if (finalized || stopped || !appDone) {
                return;
            }
            String t = status.getText();
            if (idle && !busy()) {
                finish();
            } else if (t.startsWith(P_SCAN) || t.startsWith(P_WEB) || t.startsWith(P_SETTLE)) {
                status.setText(busy() ? progress() : P_SETTLE);
            }
        });
    }

    /** 刷新状态栏左侧的进度文字和进度条。两个阶段有重叠：扫描出结果时 Web 检测就开始了。 */
    private void updateProgress() {
        if (stopped) {
            return;
        }
        long elapsed = System.currentTimeMillis() - progress.startedAt();
        if (elapsed < 0 || progress.startedAt() == 0) {
            return; // 本轮还没开始
        }
        ThreadPoolExecutor p = pool();
        long done = 0;
        if (p != null) {
            if (scanBaseline < 0) {
                scanBaseline = p.getCompletedTaskCount();
            }
            done = p.getCompletedTaskCount() - scanBaseline;
        }
        long total = progress.scanTotal();
        boolean scanPhase = scanning();

        if (scanPhase) {
            String eta = "";
            double frac = -1;
            String head;
            if (total > 0) {
                frac = (double) done / total;
                if (done > 2 && done < total) {
                    eta = String.format(" 剩余约%s", Progress.elapsed((long) ((total - done) * elapsed / done)));
                }
                head = String.format("扫描 %d%% (%d/%d)", (int) (frac * 100), done, total);
            } else {
                head = String.format("扫描中，已完成 %d", done);
            }
            String web = auditDone > 0 && webTargets > 0 ? String.format(" · Web %d/%d", auditDone, webTargets) : "";
            progress.show(head + web + " 已用" + Progress.elapsed(elapsed) + eta, frac);
            return;
        }
        if (audit.getActiveCount() > 0 || !audit.getQueue().isEmpty()) {
            double frac = webTargets > 0 ? (double) auditDone / webTargets : -1;
            progress.show(String.format("Web检测 %d/%d 已用%s", auditDone, webTargets, Progress.elapsed(elapsed)),
                    frac);
            return;
        }
        // 都没活：不动进度条（完成/停止的文案由别处写）
    }

    /** 找得到扫描线程池时 1.5 秒没动静就算完；找不到（理论上有超时兜着的尾巴任务）就多等。 */
    private long settleMs() {
        return pool() != null ? SETTLE_MS : 12000;
    }

    /** 真实的「还有没有活」：扫描任务在跑或在排队，或者 Web 检测在跑或在排队。 */
    private boolean busy() {
        return scanning() || audit.getActiveCount() > 0 || !audit.getQueue().isEmpty();
    }

    private boolean scanning() {
        Integer tc = FXMLDocumentController.taskCount;
        if (tc != null && tc.intValue() > 0) {
            return true;
        }
        ThreadPoolExecutor p = pool();
        return p != null && (p.getActiveCount() > 0 || !p.getQueue().isEmpty());
    }

    /** 控制器里的扫描线程池。点「start」时才创建，所以第一次用的时候再反射找，找不到隔 1 秒再找。 */
    private synchronized ThreadPoolExecutor pool() {
        if (scanPool == null && root != null) {
            long now = System.currentTimeMillis();
            if (now >= nextPoolLookup) {
                nextPoolLookup = now + 1000;
                scanPool = findScanPool(root);
            }
        }
        return scanPool instanceof ThreadPoolExecutor ? (ThreadPoolExecutor) scanPool : null;
    }

    private String progress() {
        int n = audit.getQueue().size() + audit.getActiveCount();
        ThreadPoolExecutor p = pool();
        if (p != null) {
            n += p.getQueue().size() + p.getActiveCount();
        }
        return (scanning() ? P_SCAN : P_WEB) + " 剩余 " + n;
    }

    private void finish() {
        finalized = true;
        int items = 0;
        List<RiskInfo> copy;
        synchronized (found) {
            copy = new ArrayList<RiskInfo>(found);
        }
        for (RiskInfo i : copy) {
            items += i.items.size();
        }
        ThreadPoolExecutor p = pool();
        String text = String.format("已完成（Web 服务 %d 个，存在风险的 %d 个，共 %d 条）", webTargets, copy.size(), items);
        status.setText(text);
        progress.show(String.format("完成，总用时 %s", Progress.elapsed(System.currentTimeMillis() - progress.startedAt())),
                1.0);
        System.out.println("[" + WebApp.NAME + "] " + text + "  auditActive=" + audit.getActiveCount()
                + " auditQueue=" + audit.getQueue().size() + (p != null
                ? " scanActive=" + p.getActiveCount() + " scanQueue=" + p.getQueue().size() : " scanPool=unknown"));
    }

    // ---------------- 结果接入 ----------------

    private void onRow(Row r) {
        String addr = r.addressProperty().getValueSafe();
        RiskInfo known = byAddress.get(addr);
        boolean isWeb = r.responseProperty().getValueSafe().startsWith("HTTP/");
        if (known != null) {
            // 点树节点时程序会从库里重建表格：把风险补回去即可，这不算新结果，不动状态栏
            applyRisk(r, known, false);
            return;
        }
        if (queued.contains(addr)) {
            return; // 检过、没有风险的旧行：重建表格时又回来了，同样不动状态栏
        }
        lastActivity = System.currentTimeMillis();
        reopenIfFinalized(); // 新结果在「已完成」之后才到：撤回，等落定后重新收尾
        queued.add(addr);
        if (!isWeb) {
            return;
        }
        webTargets++;
        boolean ssl = Boolean.TRUE.equals(r.sslProperty().get());
        audit.execute(new WebAudit(this, r, addr, ssl, chkUnauth != null && chkUnauth.isSelected(),
                chkBrute != null && chkBrute.isSelected()));
    }

    private static void tune(TableView<Row> table, String title, double min, double pref) {
        for (TableColumn<Row, ?> c : table.getColumns()) {
            if (title.equals(c.getText())) {
                c.setMinWidth(min);
                c.setPrefWidth(pref);
            }
        }
    }

    /** 已经显示「已完成」了才来的行：撤回，等落定后重新收尾。 */
    private void reopenIfFinalized() {
        if (finalized && !stopped) {
            finalized = false;
            lastActivity = System.currentTimeMillis();
            status.setText(busy() ? progress() : P_SETTLE);
        }
    }

    void finish(Row row, RiskInfo info) {
        auditDone++; // 每个 Web 检测结束都计数（没发现风险的也算），进度条靠它
        if (info.items.isEmpty()) {
            return;
        }
        found.add(info);
        byAddress.put(info.address, info);
        applyRisk(row, info, true);
    }

    private void applyRisk(Row r, RiskInfo info, boolean fresh) {
        if (!Platform.isFxApplicationThread()) {
            Platform.runLater(() -> applyRisk(r, info, fresh));
            return;
        }
        if (fresh) {
            reopenIfFinalized(); // 检测结果在「已完成」之后才出：撤回，重新收尾
            lastActivity = System.currentTimeMillis();
        }
        riskProperty(r).set(info.summary());
        String resp = r.responseProperty().get();
        if (resp != null && !resp.contains(DETAIL_MARK)) {
            r.responseProperty().set(resp + "\n" + DETAIL_MARK + "\n" + info.detail());
        }
    }

    private StringProperty riskProperty(Row r) {
        StringProperty p = riskOf.get(r);
        if (p == null) {
            p = new SimpleStringProperty("");
            riskOf.put(r, p);
        }
        return p;
    }

    // ---------------- 导出 ----------------

    private void exportCsv() {
        FileChooser fc = new FileChooser();
        fc.setTitle("导出风险清单");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV", "*.csv"));
        fc.setInitialFileName("Web风险清单-" + new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date()) + ".csv");
        File f = fc.showSaveDialog(stage);
        if (f == null) {
            return;
        }
        List<RiskInfo> copy;
        synchronized (found) {
            copy = new ArrayList<RiskInfo>(found);
        }
        try (Writer w = new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8)) {
            w.write('\ufeff');
            w.write("级别,类型,地址,入口,账号,口令,证据,整改建议\r\n");
            for (RiskInfo i : copy) {
                for (RiskItem it : i.items) {
                    w.write(csv(it.severity) + "," + csv(it.type) + "," + csv(i.address) + "," + csv(it.url) + ","
                            + csv(it.account) + "," + csv(it.password) + "," + csv(it.evidence) + ","
                            + csv(it.advice) + "\r\n");
                }
            }
        } catch (Exception e) {
            Alert a = new Alert(Alert.AlertType.ERROR);
            a.setHeaderText("导出失败");
            a.setContentText(String.valueOf(e));
            a.showAndWait();
        }
    }

    private static String csv(String s) {
        String v = s == null ? "" : s.replace("\r", " ").replace("\n", " ");
        if (v.contains(",") || v.contains("\"")) {
            v = "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }

    // ---------------- 读取程序内部状态 ----------------

    /** 控制器实例（懒加载，挖一次缓存住）。 */
    private Object controller() {
        if (controller == null && root != null) {
            try {
                Button stop = (Button) root.lookup("#id_stop");
                controller = controllerOf(stop.getOnAction(), 0, new IdentityHashMap<Object, Boolean>());
            } catch (Exception e) {
                return null;
            }
        }
        return controller;
    }

    private ExecutorService findScanPool(Parent root) {
        try {
            Field f = FXMLDocumentController.class.getDeclaredField("threadPool");
            f.setAccessible(true);
            return (ExecutorService) f.get(controller());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 扫描任务总数。taskList 里累加着每轮的 ScanTask：ip:port 模式的总数 = 行数，
     * IP×端口模式 = 目标数 × 端口数。只算新增的任务（seenTasks 记录已算过的）。
     */
    private void discoverScanTotal() {
        try {
            Object c = controller();
            if (c == null) {
                return;
            }
            Field f = FXMLDocumentController.class.getDeclaredField("taskList");
            f.setAccessible(true);
            java.util.List<?> tasks = (java.util.List<?>) f.get(c);
            long total = 0;
            for (int i = seenTasks; i < tasks.size(); i++) {
                Object t = tasks.get(i);
                Collection<?> ips = (Collection<?>) fieldOf(t, "ips");
                Collection<?> ports = (Collection<?>) fieldOf(t, "ports");
                if (ips == null) {
                    continue;
                }
                total += ports != null ? (long) ips.size() * ports.size() : ips.size();
            }
            seenTasks = tasks.size();
            if (total > 0) {
                progress.setScanTotal(total);
            }
        } catch (Exception e) {
            // 反射失败就退化为"总数未知"，进度条显示流动状态
        }
    }

    private static Collection<?> fieldOf(Object obj, String name) {
        try {
            Field f = obj.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return (Collection<?>) f.get(obj);
        } catch (Exception e) {
            return null;
        }
    }

    /** 界面按钮的事件处理器里藏着控制器对象（Java 8 是 FXMLLoader$ControllerMethodEventHandler，嵌套两层）。 */
    private Object controllerOf(Object node, int depth, IdentityHashMap<Object, Boolean> seen) {
        if (node == null || depth > 4 || seen.put(node, Boolean.TRUE) != null) {
            return null;
        }
        if (node instanceof FXMLDocumentController) {
            return node;
        }
        for (Class<?> k = node.getClass(); k != null; k = k.getSuperclass()) {
            for (Field f : k.getDeclaredFields()) {
                if (f.getType().isPrimitive() || f.getType() == String.class || Modifier.isStatic(f.getModifiers())) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    Object hit = controllerOf(f.get(node), depth + 1, seen);
                    if (hit != null) {
                        return hit;
                    }
                } catch (Exception ignore) {
                    // 读不了的字段跳过
                }
            }
        }
        return null;
    }
}
