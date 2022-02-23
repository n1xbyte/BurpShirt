package app;

import app.helpers.ASHIRT;
import app.helpers.HarSerializer;
import app.helpers.Output;
import app.model.*;
import app.ui.*;
import burp.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.stream.JsonWriter;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class BurpShirt {
    // UI stuff
    private final JTabbedPane mainPanel;
    public MainUI mainUI;

    // Burp stuff
    public IExtensionHelpers helpers;

    // ASHIRT Stuff
    private static Operation[] operationList;
    private static ServerInfo serverInfo;

    public BurpShirt () {
        helpers = BurpExtender.getCallbacks().getHelpers();
        mainPanel = new JTabbedPane();
        mainUI = new MainUI(mainPanel, mainActionListener);
    }
    // For JAR export
    public static void main(String[] args){
        System.out.println("This JAR is meant to be run through BURP extender");
    }

    public JTabbedPane getUI() {
        return mainPanel;
    }
    public ServerInfo getServerInfo() {
        return serverInfo;
    }

    public static String getOperations() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        HttpURLConnection connection;
        if (serverInfo.getServer().isEmpty()){ return "Server cannot be empty"; }
        if (serverInfo.getPort().isEmpty()){ return "Port cannot be empty"; }
        if (serverInfo.getAccessKey().isEmpty()){ return "Access Key cannot be empty"; }
        if (serverInfo.getSecretKey().isEmpty()){ return "Secret Key cannot be empty"; }
        String uri = "/api/operations";

        connection = ASHIRT.setupRequest("GET", serverInfo.getServerURL()+uri);
        ASHIRT.addDateHeader(connection);
        ASHIRT.addAuthentication(connection, null, uri, serverInfo);
        String result = ASHIRT.readResponse(connection);

        if (connection.getResponseCode() == 200){
            ObjectMapper objectMapper = new ObjectMapper();
            operationList = objectMapper.readValue(result, Operation[].class);
            return "[+] Connected to " + serverInfo.getServerURL();
        }
        else {
            return ASHIRT.readError(connection.getResponseCode());
        }
    }

    public static Tag[] getTags(String operation) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        HttpURLConnection connection;
        Tag[] tags;
        String uri = "/api/operations/" + operation + "/tags";

        connection = ASHIRT.setupRequest("GET", serverInfo.getServerURL()+uri);
        ASHIRT.addDateHeader(connection);
        ASHIRT.addAuthentication(connection, null, uri, serverInfo);
        String result = ASHIRT.readResponse(connection);

        if (connection.getResponseCode() == 200){
            ObjectMapper objectMapper = new ObjectMapper();
            tags = objectMapper.readValue(result, Tag[].class);
            return tags;
        }
        else {
            return null;
        }
    }

    public static String createTag(String operation, String name) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        HttpURLConnection connection;
        Tag[] tags = null;

        // Get all tags for operation
        if (operation.isEmpty()){ return "[-] Cannot create tag for no operation"; }
        for (Operation oper : operationList){
            if (oper.getName().equals(operation)){
                tags = getTags(operation);
            }
        }

        // See if already existing
        if (tags != null){
            for (Tag tag: tags) {
                if (tag.getName().equals(name)){
                    return "[-] " + name + " tag already exists for " + operation;
                }
            }
        }

        StringWriter sw = new StringWriter();
        JsonWriter jw = new JsonWriter(sw);
        jw.beginObject();
        jw.name("name").value(name.trim());
        jw.name("colorName").value(Tag.getRandomColor());
        jw.endObject();
        String requestBody = sw.toString();

        String uri = "/api/operations/" + operation + "/tags";

        connection = ASHIRT.setupRequest("POST", serverInfo.getServerURL()+uri);
        ASHIRT.addDateHeader(connection);
        ASHIRT.addAuthentication(connection, requestBody, uri, serverInfo);
        ASHIRT.writeRequest(connection, requestBody);
        ASHIRT.readResponse(connection);
        if (connection.getResponseCode() == 201){
            return "[+] Tag Created! \n   Name: " + name + "\n   Operation: " + operation;
        }
        else {
            return null;
        }
    }

    public static String uploadHAR(IHttpRequestResponse[] messages) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        HttpURLConnection connection;
        String slug = null;

        // Create HAR
        StringWriter harSW = new StringWriter();
        JsonWriter harJW = new JsonWriter(harSW);
        HarSerializer harFile = new HarSerializer();
        harFile.writeAll(harJW, messages);

        // Get upload details
        String[] popupResponse = EvidencePopup.getUploadDetails(operationList);
        String campaign = popupResponse[0];
        String description = popupResponse[1];
        String tags = popupResponse[2];

        // Get slug for URI
        for (Operation camp: operationList){
            if (campaign.equals(camp.getName())){
                slug = camp.getSlug();
            }
        }
        if (slug == null){
            return "[-] No matching campaign was found";
        }

        String uri = "/api/operations/" + slug + "/evidence";

        // ASHIRT make request
        connection = ASHIRT.setupRequest("POST", serverInfo.getServerURL()+uri);
        ASHIRT.addDateHeader(connection);
        String requestBody = ASHIRT.generateMultipart(connection, harSW.toString(), description, tags);
        ASHIRT.addAuthentication(connection, requestBody , uri, serverInfo);
        ASHIRT.writeRequest(connection, requestBody);
        String result = ASHIRT.readResponse(connection);

        // Set response
        if (connection.getResponseCode() == 201){
            ObjectMapper objectMapper = new ObjectMapper();
            Evidence evidence = objectMapper.readValue(result, Evidence.class);
            return "[+] Upload Successful! \n   UUID: " + evidence.getUUID() + "\n   Campaign: " + campaign;
        }
        else {
            return ASHIRT.readError(connection.getResponseCode());
        }
    }

    public static String uploadHAR(IRequestInfo request, IResponseInfo response, byte[] requestBytes, byte[]responseBytes) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        HttpURLConnection connection;
        String slug = null;

        // Create HAR
        StringWriter harSW = new StringWriter();
        JsonWriter harJW = new JsonWriter(harSW);
        HarSerializer harFile = new HarSerializer();
        harFile.write(harJW, request, response, requestBytes, responseBytes);

        // Get upload details
        String[] popupResponse = EvidencePopup.getUploadDetails(operationList);
        String campaign = popupResponse[0];
        String description = popupResponse[1];
        String tags = popupResponse[2];

        // Get slug for URI
        for (Operation camp: operationList){
            if (campaign.equals(camp.getName())){
                slug = camp.getSlug();
            }
        }
        if (slug == null){
            return "[-] No matching campaign was found";
        }

        String uri = "/api/operations/" + slug + "/evidence";

        // ASHIRT make request
        connection = ASHIRT.setupRequest("POST", serverInfo.getServerURL()+uri);
        ASHIRT.addDateHeader(connection);
        String requestBody = ASHIRT.generateMultipart(connection, harSW.toString(), description, tags);
        ASHIRT.addAuthentication(connection, requestBody , uri, serverInfo);
        ASHIRT.writeRequest(connection, requestBody);
        String result = ASHIRT.readResponse(connection);

        // Set response
        if (connection.getResponseCode() == 201){
            ObjectMapper objectMapper = new ObjectMapper();
            Evidence evidence = objectMapper.readValue(result, Evidence.class);
            return "[+] Upload Successful! \n   UUID: " + evidence.getUUID() + "\n   Campaign: " + campaign;
        }
        else {
            return ASHIRT.readError(connection.getResponseCode());
        }
    }

    public static String createOperation(String operationName) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        HttpURLConnection connection;

        if (operationName.isEmpty()){ return "[-] Cannot create operation with blank name"; }
        for (Operation operation : operationList){
            if (operation.getName().equals(operationName)){
                return "[-] Operation name already exists";
            }
        }
        StringWriter sw = new StringWriter();
        JsonWriter jw = new JsonWriter(sw);
        jw.beginObject();
        jw.name("slug").value(operationName.trim());
        jw.name("name").value(operationName.trim());
        jw.endObject();
        String requestBody = sw.toString();

        String uri = "/api/operations";
        connection = ASHIRT.setupRequest("POST", serverInfo.getServerURL()+uri);
        ASHIRT.addDateHeader(connection);
        ASHIRT.addAuthentication(connection, requestBody , uri, serverInfo);
        ASHIRT.writeRequest(connection, requestBody);
        String result = ASHIRT.readResponse(connection);

        if (connection.getResponseCode() == 201) {
            ObjectMapper objectMapper = new ObjectMapper();
            Operation operation = objectMapper.readValue(result, Operation.class);
            getOperations();
            return "[+] Creation successful! \n   Operation: " + operation.getName();
        }
        else {
            return ASHIRT.readError(connection.getResponseCode());
        }
    }

    ActionListener mainActionListener = new ActionListener() {
        public void actionPerformed(ActionEvent event) {
            String command = event.getActionCommand();
            String result;
            switch (command) {
                case "checkConnection":
                    String server = mainUI.serverTextField.getText().trim();
                    String port = mainUI.portTextField.getText().trim();
                    String access = mainUI.accessTextField.getText().trim();
                    String secret = mainUI.secretTextField.getText().trim();

                    serverInfo = new ServerInfo();
                    serverInfo.setServer(server);
                    serverInfo.setPort(port);
                    serverInfo.setAccessKey(access);
                    serverInfo.setSecretKey(secret);
                    serverInfo.setSSL(false);
                    serverInfo.setStatus(false);

                    try {
                        result = getOperations();
                        if (result.contains("Connected")){
                            mainUI.connectionStatus.setText("Status: Connected");
                            Output.writeResult(mainUI, result);
                            serverInfo.setStatus(true);
                        }
                        else {
                            Output.writeError(mainUI, serverInfo, result);
                        }
                    } catch (Exception e) {
                        Output.writeError(mainUI, serverInfo, "Getting Operations");
                    }
                    break;
                case "uploadEvidence":
                    if (serverInfo.getStatus()) {
                        try {
                            byte[] request = mainUI.requestTextArea.getText().getBytes(StandardCharsets.UTF_8);
                            byte[] response = mainUI.responseTextArea.getText().getBytes(StandardCharsets.UTF_8);
                            String[] output = EditorEvidencePopup.getUploadDetails();
                            IExtensionHelpers helpers = BurpExtender.getCallbacks().getHelpers();
                            IHttpService httpService = helpers.buildHttpService(output[0], Integer.parseInt(output[1]), output[2]);
                            IRequestInfo requestInfo = helpers.analyzeRequest(httpService, request);
                            IResponseInfo responseInfo = helpers.analyzeResponse(response);
                            result = uploadHAR(requestInfo, responseInfo, request, response);
                            Output.writeResult(mainUI, result);
                        } catch (Exception e) {
                            Output.writeError(mainUI, serverInfo,"Uploading Evidence");
                        }
                    } else {
                        Output.noConnectivity();
                    }
                    break;
                case "createOperation":
                    if (serverInfo.getStatus()) {
                        try {
                            String operation = mainUI.operationTextField.getText().trim();
                            result = createOperation(operation);
                            Output.writeResult(mainUI, result);
                        } catch (Exception e) {
                            Output.writeError(mainUI, serverInfo,"Creating Operating");
                        }
                    } else {
                        Output.noConnectivity();
                    }
                    break;
            }
        }
    };

}
