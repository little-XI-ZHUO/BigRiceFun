package com.bigricefun;

import com.webfinder.portscan.PortScan;

import javafx.application.Application;
import javafx.scene.image.Image;
import javafx.stage.Screen;
import javafx.stage.Stage;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * BigRiceFun 入口。加载界面、建库、显示窗口，换上自己的名字和图标，并挂上 Web 检测。
 */
public class WebApp extends PortScan {
    public static final String NAME = "BigRiceFun";
    public static final String VERSION = "1.0.0";
    private static final int[] ICON_SIZES = {16, 20, 24, 32, 48, 64, 128, 256};

    @Override
    public void start(Stage stage) throws Exception {
        super.start(stage);
        stage.setTitle(NAME + " " + VERSION);
        stage.getIcons().addAll(icons());

        // 多了一列「风险」，按屏幕大小取尺寸并居中，免得超出屏幕
        javafx.geometry.Rectangle2D sb = Screen.getPrimary().getVisualBounds();
        stage.setWidth(Math.min(1560, sb.getWidth() - 60));
        stage.setHeight(Math.min(880, sb.getHeight() - 80));
        stage.setMinWidth(900);
        stage.centerOnScreen();

        Boot.install(stage);
    }

    /** 标题栏、任务栏、Alt-Tab 各取所需尺寸。 */
    static List<Image> icons() {
        List<Image> out = new ArrayList<Image>();
        for (int s : ICON_SIZES) {
            try (InputStream in = WebApp.class.getResourceAsStream("/brand/icon" + s + ".png")) {
                if (in != null) {
                    out.add(new Image(in));
                }
            } catch (Exception ignore) {
                // 少一个尺寸不影响启动
            }
        }
        return out;
    }

    /** jar 里的品牌图标，按指定边长缩放；取不到返回 null。 */
    static Image icon(int size, double edge) {
        try (InputStream in = WebApp.class.getResourceAsStream("/brand/icon" + size + ".png")) {
            if (in == null) {
                return null;
            }
            Image img = new Image(in);
            return edge > 0 ? new Image(WebApp.class.getResourceAsStream("/brand/icon" + size + ".png"), edge, edge, true, true) : img;
        } catch (Exception e) {
            return null;
        }
    }
}
