package main;

import javafx.scene.control.Button;
import javafx.stage.Stage;
import security.FileEncryption;


public class EncryptPane extends SecurityPane {

    public EncryptPane(Stage primaryStage) {
        super(primaryStage);
    }

    @Override
    protected void createDoButton() {
        doButton = new Button();
        doButton.setText("Encrypt...");
        doButton.setOnAction(event -> new PasswordWindow(pathTextField.getText(), FileEncryption.ENCRYPT_MODE));
    }
}
