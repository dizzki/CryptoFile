package main;

import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

public class MainWindow extends BorderPane {

    public MainWindow(Stage primaryStage) {
        TabPane tabPane = new TabPane();
        Tab encryptTab = new Tab("Encrypt", new EncryptPane(primaryStage));
        encryptTab.setClosable(false);
        Tab decryptTab = new Tab("Decrypt", new DecryptPane(primaryStage));
        decryptTab.setClosable(false);
        tabPane.getTabs().addAll(encryptTab, decryptTab);
        setCenter(tabPane);
    }
}
