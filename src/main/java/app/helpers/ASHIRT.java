package app.helpers;

import app.model.ServerInfo;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;

public class ASHIRT {

    public static HttpURLConnection setupRequest(String method, String url) throws IOException {
        URL request = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) request.openConnection();
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setRequestMethod(method);
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        return connection;
    }

    public static void addDateHeader(HttpURLConnection connection) {
        DateTimeFormatter format = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss z", Locale.ENGLISH).withZone(ZoneId.of("GMT"));
        String date = format.format(Instant.now());
        connection.setRequestProperty("Date", date);
    }

    public static String readResponse(HttpURLConnection connection) throws IOException {
        StringBuilder response = new StringBuilder();
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        return response.toString();
    }

    public static void writeRequest(HttpURLConnection connection, String requestBody) throws IOException {
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream(), StandardCharsets.UTF_8));
        out.write(requestBody);
        out.flush();
        out.close();
        connection.getOutputStream().close();
    }

    public static String generateMultipart(HttpURLConnection connection, String harFile, String description, String tags){
        String boundary = Long.toHexString(System.currentTimeMillis());
        connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=---------------------------" + boundary);
        return getUploadRequestBody(boundary, harFile, description, tags);
    }

    public static void addAuthentication(HttpURLConnection connection, String requestBody, String uri, ServerInfo serverInfo) throws NoSuchAlgorithmException, InvalidKeyException {
        String method = connection.getRequestMethod();
        String hmac;
        if (method.equals("GET")){
            byte[] emptyRequestBody = {};
            hmac = generateHMAC(emptyRequestBody, method, connection.getRequestProperty("Date"), uri, serverInfo.getSecretKey());
        }
        else {
            hmac = generateHMAC(requestBody.getBytes(StandardCharsets.UTF_8), method, connection.getRequestProperty("Date"), uri, serverInfo.getSecretKey());
        }
        connection.setRequestProperty("Authorization", serverInfo.getAccessKey() + ":" + hmac);
    }

    public static String generateHMAC(byte[] requestBody, String method, String date, String uri, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] requestBodySHA256 = digest.digest(requestBody);
        StringBuilder hmacMessage = new StringBuilder();
        hmacMessage.append(method);
        hmacMessage.append("\n");
        hmacMessage.append(uri);
        hmacMessage.append("\n");
        hmacMessage.append(date);
        hmacMessage.append("\n");

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(secret), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        mac.update(hmacMessage.toString().getBytes(StandardCharsets.US_ASCII));
        mac.update(requestBodySHA256);
        byte[] hmacFinal = mac.doFinal();
        return Base64.getEncoder().encodeToString(hmacFinal);
    }

    public static String getUploadRequestBody(String boundary, String harFile, String description, String tags) {
        StringBuilder request = new StringBuilder();
        request.append("-----------------------------" + boundary + "\n");
        request.append("Content-Disposition: form-data; name=\"notes\"\n");
        request.append("\n");
        request.append(description + "\n");
        request.append("-----------------------------" + boundary + "\n");
        request.append("Content-Disposition: form-data; name=\"contentType\"\n");
        request.append("\n");
        request.append("http-request-cycle\n");
        request.append("-----------------------------" + boundary + "\n");
        request.append("Content-Disposition: form-data; name=\"tagIds\"\n");
        request.append("\n");
        request.append(tags + "\n");
        request.append("-----------------------------" + boundary + "\n");
        request.append("Content-Disposition: form-data; name=\"file\"; filename=\"test.har\"\n");
        request.append("Content-Type: application/octet-stream\n");
        request.append("\n");
        request.append(harFile + "\n\n");
        request.append("-----------------------------" + boundary + "--\n");
        return request.toString();
    }

    public static String readError(int responseCode) {
        if (responseCode == 401) {
            return "Unauthorized; Check Credentials";
        }
        else {
            return "Unknown Response Code";
        }
    }
}
