package app.controllers;

import app.BurpShirt;
import app.helpers.Output;
import app.model.ServerInfo;
import app.ui.MainUI;
import burp.*;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

public class ContextMenuController implements IContextMenuFactory {

    private static BurpShirt burpShirt;
    private static MainUI mainUI;
    public ContextMenuController(BurpShirt bs) {
        burpShirt = bs;
        mainUI = bs.mainUI;
    }
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0){
            return null;
        }
        JMenuItem editorMenu = new JMenuItem("Send to Editor");
        JMenuItem sendMenu = new JMenuItem("Send to ASHIRT");
        sendMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    BurpShirt.getOperations();
                    sendToASHIRT(messages);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
        editorMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToEditor(messages);
            }
        });
        return Arrays.asList(editorMenu, sendMenu);
    }

    public static void sendToEditor(IHttpRequestResponse[] messages) {
        if (messages.length > 1) {
            JOptionPane.showMessageDialog(null, "Only select one request to send to editor", "BurpShirt",JOptionPane.INFORMATION_MESSAGE);
        }

        byte[] request = messages[0].getRequest();
        byte[] response = messages[0].getResponse();
        if (response.length == 0){
            JOptionPane.showMessageDialog(null, "No response for selected request","BurpShirt",JOptionPane.INFORMATION_MESSAGE);
        }
        mainUI.requestTextArea.setText(new String(request, StandardCharsets.UTF_8));
        mainUI.responseTextArea.setText(new String(response, StandardCharsets.UTF_8));
    }
    public static void sendToASHIRT(IHttpRequestResponse[] messages) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        ServerInfo serverInfo = burpShirt.getServerInfo();

        if (serverInfo.getStatus()){
            String result = BurpShirt.uploadHAR(messages);
            Output.writeResult(mainUI, result);
        }
        else {
            Output.writeError(mainUI, serverInfo,"Uploading Evidence");
        }
    }
}