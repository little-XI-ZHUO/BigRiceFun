import com.bigricefun.WebApp;
import com.webfinder.portscan.FXMLDocumentController;
import com.webfinder.portscan.ScanTask;
import com.webfinder.portscan.ScanTaskIpPort;
import com.webfinder.portscan.model.Row;

import javafx.application.Platform;
import javafx.scene.Parent;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.control.TreeView;
import javafx.stage.Stage;

import java.util.LinkedList;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Test driver only (never packaged). Shows the real window, starts a scan the way the
 * New Scan "start" button does, logs every status-bar change with a timestamp, and exits
 * a little after the status says done.
 *
 * usage: java -Dtargets=127.0.0.1:18081,127.0.0.1:18082 -cp test;BigRiceFun.jar TestDrive
 */
public class TestDrive extends WebApp {
    private static long t0;

    @Override
    public void start(Stage stage) throws Exception {
        super.start(stage);
        t0 = System.currentTimeMillis();
        new Thread(() -> drive(stage), "driver").start();
    }

    @SuppressWarnings("unchecked")
    void drive(Stage stage) {
        final int threads = Integer.getInteger("threads", 100);
        final int timeout = Integer.getInteger("timeout", 3000);
        String spec = System.getProperty("targets", "");
        if (spec.isEmpty()) {
            System.out.println("no -Dtargets given; window only");
            return;
        }
        LinkedList<String> ips = new LinkedList<String>();
        for (String line : spec.split("[,\\s]+")) {
            if (!line.trim().isEmpty() && !ips.contains(line.trim())) {
                ips.add(line.trim());
            }
        }
        Parent root = stage.getScene().getRoot();
        final TableView<Row> table = (TableView<Row>) root.lookup("#id_tableview");
        final TreeView<String> tree = (TreeView<String>) root.lookup("#id_treeview");
        final Label status = (Label) root.lookup("#id_status");
        final CheckBox auto = (CheckBox) root.lookup("#id_autodeleteempty");

        Platform.runLater(() -> status.textProperty().addListener((o, a, b) -> {
            // 扫描过程中状态栏会被每个任务写成 ip:port，只记录非地址的变化
            if (b != null && !b.matches(".*:\\d+")) {
                System.out.printf("STATUS %+6dms %s%n", System.currentTimeMillis() - t0, b);
            }
        }));

        FXMLDocumentController.taskCount = Integer.valueOf(0);
        final ExecutorService pool = Executors.newFixedThreadPool(threads);
        ScanTask task = new ScanTaskIpPort(ips, null, tree.getRoot(), pool, FXMLDocumentController.taskCount,
                table, timeout, status, auto);
        FXMLDocumentController.taskCount = Integer.valueOf(FXMLDocumentController.taskCount + 1);
        // 和真点 start 完全一样：线程池和任务都交给控制器（进度总数从 taskList 来）
        wireController(root, pool, task);
        System.out.printf("SCAN   %+6dms start: %d targets, %d threads, %dms%n", System.currentTimeMillis() - t0,
                ips.size(), threads, timeout);
        new Thread((Runnable) task, "scan").start();
        Platform.runLater(() -> status.setText("scanning..."));

        // 和 start 按钮装的完全相同的完成计时器：taskCount==0 且队列空就写 complete
        new Timer("timer", true).schedule(new TimerTask() {
            @Override
            public void run() {
                int queued = ((ThreadPoolExecutor) pool).getQueue().size();
                int active = ((ThreadPoolExecutor) pool).getActiveCount();
                if (FXMLDocumentController.taskCount.intValue() == 0 && queued == 0) {
                    cancel();
                    System.out.printf("TIMER  %+6dms app timer fires 'complete' while scanActive=%d queued=%d%n",
                            System.currentTimeMillis() - t0, active, queued);
                    Platform.runLater(() -> status.setText("complete"));
                }
            }
        }, 0, 3000);

        // 状态变成「已完成（」后还要稳定 4 秒才算数：中途来了新行会被撤回，那就继续等
        new Thread(() -> {
            long since = 0;
            while (true) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    return;
                }
                final String[] text = {""};
                final int[] rows = {0};
                Platform.runLater(() -> {
                    text[0] = status.getText();
                    rows[0] = table.getItems().size();
                });
                try {
                    Thread.sleep(80);
                } catch (InterruptedException e) {
                    return;
                }
                boolean done = text[0].startsWith("已完成（") && rows[0] > 0;
                long now = System.currentTimeMillis();
                if (done && since == 0) {
                    since = now;
                } else if (!done) {
                    since = 0;
                }
                if (done && now - since >= 1000L * Integer.getInteger("linger", 4)) {
                    if (Boolean.getBoolean("reload") && !reloaded) {
                        reloaded = true;
                        reloadAsTreeClick(table); // 模拟扫完后点树节点：表格按库里的原始响应重建
                        since = 0;
                        try {
                            Thread.sleep(3000);
                        } catch (InterruptedException e) {
                            return;
                        }
                        final int[] withRisk = {0};
                        final int[] total = {0};
                        Platform.runLater(() -> {
                            for (Row r : table.getItems()) {
                                total[0]++;
                                if (r.responseProperty().get().contains("===== 风险详情 =====")) {
                                    withRisk[0]++;
                                }
                            }
                        });
                        try {
                            Thread.sleep(150);
                        } catch (InterruptedException e) {
                            return;
                        }
                        System.out.printf("RELOAD %+6dms rows rebuilt=%d, with risk detail again=%d, status=[%s]%n",
                                System.currentTimeMillis() - t0, total[0], withRisk[0], status.getText());
                        since = System.currentTimeMillis();
                        continue;
                    }
                    dump(table);
                    System.out.printf("EXIT   %+6dms rows=%d%n", now - t0, rows[0]);
                    System.exit(0);
                }
            }
        }, "watch").start();
    }

    private boolean reloaded;

    private void reloadAsTreeClick(final TableView<Row> table) {
        Platform.runLater(() -> {
            java.util.List<Row> old = new java.util.ArrayList<Row>(table.getItems());
            table.getItems().clear();
            int risk = 0;
            for (Row r : old) {
                String resp = r.responseProperty().get();
                int cut = resp.indexOf("===== 风险详情 =====");
                if (cut > 0) {
                    risk++;
                    resp = resp.substring(0, cut);
                }
                table.getItems().add(new Row(r.addressProperty().get(), r.ShiroProperty().get(),
                        r.sslProperty().get(), r.serverProperty().get(), r.titleProperty().get(),
                        r.statuscodeProperty().get(), r.contentLengthProperty().get(), resp,
                        r.realIpProperty().get()));
            }
            System.out.printf("RELOAD %+6dms simulated tree click: %d rows rebuilt from raw responses (%d had risk)%n",
                    System.currentTimeMillis() - t0, old.size(), risk);
        });
    }

    /** 把测试用的线程池写进控制器的 threadPool 字段，模拟 start 按钮的行为。 */
    /** 和真点 start 一样：把线程池写进控制器，任务加进 taskList。 */
    private void wireController(Parent root, ExecutorService pool, ScanTask task) {
        try {
            Object handler = ((javafx.scene.control.Button) root.lookup("#id_stop")).getOnAction();
            Object controller = findController(handler, 0, new java.util.IdentityHashMap<Object, Boolean>());
            java.lang.reflect.Field pf = FXMLDocumentController.class.getDeclaredField("threadPool");
            pf.setAccessible(true);
            pf.set(controller, pool);
            java.lang.reflect.Field tf = FXMLDocumentController.class.getDeclaredField("taskList");
            tf.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.List<Object> tasks = (java.util.List<Object>) tf.get(controller);
            tasks.add(task);
        } catch (Exception e) {
            System.out.println("wireController failed: " + e);
        }
    }

    private Object findController(Object node, int depth, java.util.IdentityHashMap<Object, Boolean> seen) {
        if (node == null || depth > 4 || seen.put(node, Boolean.TRUE) != null) {
            return null;
        }
        if (node instanceof FXMLDocumentController) {
            return node;
        }
        for (Class<?> k = node.getClass(); k != null; k = k.getSuperclass()) {
            for (java.lang.reflect.Field f : k.getDeclaredFields()) {
                if (f.getType().isPrimitive() || f.getType() == String.class) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    Object hit = findController(f.get(node), depth + 1, seen);
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

    @SuppressWarnings("unchecked")
    private void dump(final TableView<Row> table) {
        Platform.runLater(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("ROWS %d (columns:", table.getItems().size()));
            for (Object c : table.getColumns()) {
                sb.append(" ").append(((javafx.scene.control.TableColumn<?, ?>) c).getText());
            }
            sb.append(")\n");
            java.util.List<Row> rows = new java.util.ArrayList<Row>(table.getItems());
            rows.sort((a, b) -> a.addressProperty().get().compareTo(b.addressProperty().get()));
            for (Row r : rows) {
                String resp = r.responseProperty().getValueSafe();
                int cut = resp.indexOf("===== 风险详情 =====");
                sb.append(String.format("%-20s ssl=%-5s title=%-22s | %s%n", r.addressProperty().get(),
                        r.sslProperty().get(), cut(r.titleProperty().getValueSafe(), 22),
                        cut < 0 ? "(无风险)" : resp.substring(cut).replace("\n    ", " ").replace("\n", " ")));
            }
            System.out.println(sb);
        });
    }

    private static String cut(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    public static void main(String[] args) {
        launch(args);
    }
}
