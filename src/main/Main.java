package main;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.File;


public class Main extends Application {

    @Override
    public void start(Stage primaryStage) {
        Scene scene = new Scene(new MainWindow(primaryStage));
        scene.getStylesheets().add(getClass().getResource(".." + File.separator + "styles" + File.separator + "Style.css").toExternalForm());
        primaryStage.setTitle("CryptoFile");
        primaryStage.setScene(scene);
        primaryStage.getIcons().add(new Image(getClass().getResourceAsStream(".." + File.separator + "images" + File.separator + "logo.png")));
        primaryStage.setResizable(false);
        primaryStage.show();
    }

    /**
     * @param args аргументы командной строки
     */
    public static void main(String[] args) {
        launch(args);
    }
}
