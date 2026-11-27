package com.bigricefun;

import javafx.application.Application;

/** jar 的 Main-Class。 */
public final class Launch {
    private Launch() {
    }

    public static void main(String[] args) {
        Application.launch(WebApp.class, args);
    }
}
