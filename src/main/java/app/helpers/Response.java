package app.helpers;

import burp.IResponseInfo;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class Response {

    public static int getResponseCode(IResponseInfo response) { return response.getStatusCode();}
    public static int getHeaderSize(IResponseInfo response){
        return response.getBodyOffset();
    }
    public static String getHTTPVersion(IResponseInfo response) {
        List<String> headers = response.getHeaders();
        String httpVersion = null;
        for (String header: headers) {
            Scanner scanner = new Scanner(header);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("HTTP")) { // Should be first line
                    char version = line.charAt(5);
                    if (version == '2') { // Check for HTTP/2, diff substring
                        httpVersion = line.substring(0,6);
                        break;
                    }
                    else {
                        httpVersion = line.substring(0,8);
                        break;
                    }
                }
            }
        }
        return httpVersion;
    }

    public static String getResponseStatus(IResponseInfo response) {
        List<String> headers = response.getHeaders();
        String responseStatus = null;
        for (String header: headers) {
            Scanner scanner = new Scanner(header);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("HTTP")) { // Should be first line
                    char version = line.charAt(5);
                    if (version == '2') { // Check for HTTP/2, diff substring
                        responseStatus = line.substring(10).trim();
                        break;
                    }
                    else {
                        responseStatus = line.substring(12).trim();
                        break;
                    }
                }
            }
        }
        return responseStatus;
    }

    public static Map<String, String> getHeaders(IResponseInfo response){
        Map<String, String> headerMap = new HashMap<>();
        List<String> headers = response.getHeaders();
        for (String header: headers) {
            Scanner scanner = new Scanner(header);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (!line.contains("Cookie") && !line.contains("HTTP/1.") && !line.contains("HTTP/2")) { // If not cookies or first line
                    String[] temp = line.split(":");
                    headerMap.put(temp[0], temp[1].trim());
                }
            }
        }
        return headerMap;
    }

    public static boolean hasSetCookie(IResponseInfo response){
        List<String> headers = response.getHeaders();
        for (String header: headers) {
            Scanner scanner = new Scanner(header);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("Set-Cookie")) { // If not cookies or first line
                    return true;
                }
            }
        }
        return false;
    }
}
