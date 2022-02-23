package app.helpers;

import burp.IParameter;
import burp.IRequestInfo;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;


public class Request {
    public static String getMethod(IRequestInfo request){
        return request.getMethod();
    }

    public static String getURL(IRequestInfo request){
        String url = null;
        try {
            url = request.getUrl().toString();
        } catch (Exception e){
            if (request.getHeaders().size() > 0){
                String firstLine = request.getHeaders().get(0); //first line
                String[] tmp = firstLine.split(" ");
                if (tmp.length == 3)
                    url = tmp[1];
            }
        }
        return url;
    }

    public static int getHeaderSize(IRequestInfo request){
        return request.getBodyOffset();
    }

    public static String getHTTPVersion(IRequestInfo request) {
        List<String> headers = request.getHeaders();
        String httpVersion = null;
        for (String header: headers) {
            Scanner scanner = new Scanner(header);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("HTTP")) { // Should be first line
                    String temp = line.substring(line.length()-4);
                    if (temp.contains("2")) { // Check for HTTP/2, diff substring
                        httpVersion = line.substring(line.length()-6);
                    }
                    else {
                        httpVersion = line.substring(line.length()-8);
                    }
                    break;
                }
            }
        }
        return httpVersion;
    }

    public static Map<String, String> getCookies(IRequestInfo request){
        Map<String, String> cookieMap = new HashMap<>();
        List<String> headers = request.getHeaders();
        String cookie = null;
        for (String header: headers) {
            Scanner scanner = new Scanner(header);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("Cookie")) {
                    cookie = line;
                }
            }
        }
        if (cookie != null){
            cookie = cookie.substring(8);
            String[] cookieList = cookie.split(";");
            for (String cook: cookieList){
                String[] temp = cook.split("=");
                cookieMap.put(temp[0].trim(), temp[1]);
            }
        }
        return cookieMap;
    }

    public static Map<String, String> getHeaders(IRequestInfo request){
        Map<String, String> headerMap = new HashMap<>();
        List<String> headers = request.getHeaders();
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

    public static Map<String, String> getParameters(IRequestInfo request){
        Map<String, String> paramMap = new HashMap<>();
        for (IParameter param: request.getParameters()) {
            paramMap.put(param.getName(), param.getValue());
        }
        return paramMap;
    }
}
