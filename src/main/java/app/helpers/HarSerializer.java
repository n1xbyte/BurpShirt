package app.helpers;

import burp.*;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// Code altered from logger++
// https://github.com/nccgroup/LoggerPlusPlus

public class HarSerializer {

    public void writeAll(JsonWriter writer, IHttpRequestResponse[] messages) throws IOException {
        writer.beginObject();
        writer.name("log").beginObject();

        writer.name("version").value("1.2");

        // Creator object
        writer.name("creator").beginObject();
        writer.name("name").value("n1xbyte");
        writer.name("version").value("1.0");
        writer.endObject(); // end creator object

        //Workaround for https://bugzilla.mozilla.org/show_bug.cgi?id=1691240
        writer.name("pages").beginArray().endArray();

        // Entries
        writer.name("entries").beginArray();

        for (IHttpRequestResponse message: messages) {
            IRequestInfo request = BurpExtender.getHelpers().analyzeRequest(message.getRequest());
            IResponseInfo response = BurpExtender.getHelpers().analyzeResponse(message.getResponse());

            // Start request object
            writer.beginObject();

            // Set time to now
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
            Date now = new Date();
            writer.name("startedDateTime").value(fmt.format(now));
            long time = 500;
            writer.name("time").value(time);
            writer.name("request").beginObject();
            writer.name("method").value(Request.getMethod(request));
            writer.name("url").value(Request.getURL(request));
            writer.name("httpVersion").value(Request.getHTTPVersion(request));

            // Request Cookies
            writer.name("cookies").beginArray();
            Map<String, String> reqCookieMap = Request.getCookies(request);
            if (!reqCookieMap.isEmpty()) {
                for (Map.Entry<String,String> entry : reqCookieMap.entrySet()) {
                    writer.beginObject();
                    writer.name("name").value(entry.getKey());
                    writer.name("value").value(entry.getValue());
                    writer.endObject();
                }
            }
            writer.endArray();

            // Request Headers
            writer.name("headers").beginArray();
            Map<String, String> reqHeaderMap = Request.getHeaders(request);
            for (Map.Entry<String,String> entry : reqHeaderMap.entrySet()) {
                writer.beginObject();
                writer.name("name").value(entry.getKey());
                writer.name("value").value(entry.getValue());
                writer.endObject();
            }
            writer.endArray();

            // Request QueryString
            writer.name("queryString").beginArray();
            if (Request.getMethod(request).equals("GET")) {
                Map<String, String> reqParameterMap = Request.getParameters(request);
                for (Map.Entry<String, String> entry : reqParameterMap.entrySet()) {
                    writer.beginObject();
                    writer.name("name").value(entry.getKey());
                    writer.name("value").value(entry.getValue());
                    writer.endObject();
                }
            }
            writer.endArray();

            //if (message.getRequest().length - Request.getHeaderSize(request) != 0) {
                writer.name("postData").beginObject();
                writer.name("mimeType").value("hardcode");
                List<IParameter> bodyParams = getRequestBodyParameters(message.getRequest());
                writer.name("params").beginArray();
                for (IParameter bodyParam : bodyParams) {
                    writer.beginObject();
                    writer.name("name").value(bodyParam.getName());
                    writer.name("value").value(bodyParam.getValue());
                    writer.endObject();
                }
                writer.endArray(); // end params array
                String requestBody = new String(message.getRequest(), StandardCharsets.UTF_8);
                writer.name("text").value(requestBody);
                writer.endObject(); // end postData object
            //}

            // Request Size
            writer.name("headersSize").value(Request.getHeaderSize(request));
            writer.name("bodySize").value(Request.getHeaderSize(request) - message.getRequest().length);

            // End Request object
            writer.endObject();

            // Start Response object
            writer.name("response").beginObject();
            writer.name("status").value(Response.getResponseCode(response));
            writer.name("statusText").value(Response.getResponseStatus(response));
            writer.name("httpVersion").value(Response.getHTTPVersion(response));

            // Response Cookies
            writer.name("cookies").beginArray();
            if (Response.hasSetCookie(response)) {
                List<ICookie> cookies = getResponseCookies(message.getResponse());
                for (ICookie cookie : cookies) {
                    writer.beginObject();
                    writer.name("name").value(cookie.getName());
                    writer.name("value").value(cookie.getValue());
                    writer.name("path").value(cookie.getPath());
                    writer.name("domain").value(cookie.getDomain());
                    writer.endObject();
                }
            }
            writer.endArray();

            // Response headers
            writer.name("headers").beginArray();
            Map<String, String> respHeaderMap = Response.getHeaders(response);
            for (Map.Entry<String,String> entry : respHeaderMap.entrySet()) {
                writer.beginObject();
                writer.name("name").value(entry.getKey());
                writer.name("value").value(entry.getValue());
                writer.endObject();
            }
            writer.endArray();

            // Response size
            writer.name("redirectURL").value("null");
            writer.name("headersSize").value(Response.getHeaderSize(response));
            writer.name("bodySize").value(message.getResponse().length - Response.getHeaderSize(response));

            // Response content
            writer.name("content").beginObject();
            writer.name("size").value(message.getResponse().length - Response.getHeaderSize(response));
            writer.name("mimeType").value("text/html");

            String responseBody = "";
            //if (message.getResponse().length - Response.getHeaderSize(response) != 0){
                responseBody = new String(message.getResponse(), StandardCharsets.UTF_8);
            //}

            writer.name("text").value(responseBody);

            // End objects
            writer.endObject();
            writer.endObject();
            writer.name("cache").beginObject();
            writer.endObject();
            writer.name("timings").beginObject();
            writer.name("send").value(0);
            writer.name("wait").value(0);
            writer.name("receive").value(0);
            writer.endObject();
            writer.endObject();
        }
        writer.endArray();
        writer.endObject();
        writer.endObject();
    }

    public void write(JsonWriter writer, IRequestInfo request, IResponseInfo response, byte[] requestBytes, byte[] responseBytes) throws IOException {
        // Top level log object
        writer.beginObject();
        writer.name("log").beginObject();

        writer.name("version").value("1.2");

        // Creator object
        writer.name("creator").beginObject();
        writer.name("name").value("n1xbyte");
        writer.name("version").value("1.0");
        writer.endObject(); // end creator object

        //Workaround for https://bugzilla.mozilla.org/show_bug.cgi?id=1691240
        writer.name("pages").beginArray().endArray();

        // Entries
        writer.name("entries").beginArray();


        // Start request object
        writer.beginObject();

        // Set time to now
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        Date now = new Date();
        writer.name("startedDateTime").value(fmt.format(now));
        long time = 500;
        writer.name("time").value(time);
        writer.name("request").beginObject();
        writer.name("method").value(Request.getMethod(request));
        writer.name("url").value(Request.getURL(request));
        writer.name("httpVersion").value(Request.getHTTPVersion(request));

        // Request Cookies
        writer.name("cookies").beginArray();
        Map<String, String> reqCookieMap = Request.getCookies(request);
        if (!reqCookieMap.isEmpty()) {
            for (Map.Entry<String,String> entry : reqCookieMap.entrySet()) {
                writer.beginObject();
                writer.name("name").value(entry.getKey());
                writer.name("value").value(entry.getValue());
                writer.endObject();
            }
        }
        writer.endArray();

        // Request Headers
        writer.name("headers").beginArray();
        Map<String, String> reqHeaderMap = Request.getHeaders(request);
        for (Map.Entry<String,String> entry : reqHeaderMap.entrySet()) {
            writer.beginObject();
            writer.name("name").value(entry.getKey());
            writer.name("value").value(entry.getValue());
            writer.endObject();
        }
        writer.endArray();

        // Request QueryString
        writer.name("queryString").beginArray();
        if (Request.getMethod(request).equals("GET")) {
            Map<String, String> reqParameterMap = Request.getParameters(request);
            for (Map.Entry<String, String> entry : reqParameterMap.entrySet()) {
                writer.beginObject();
                writer.name("name").value(entry.getKey());
                writer.name("value").value(entry.getValue());
                writer.endObject();
            }
        }
        writer.endArray();

        //if (requestBytes.length - Request.getHeaderSize(request) != 0) {
            writer.name("postData").beginObject();
            writer.name("mimeType").value("hardcode");
            List<IParameter> bodyParams = getRequestBodyParameters(requestBytes);
            writer.name("params").beginArray();
            for (IParameter bodyParam : bodyParams) {
                writer.beginObject();
                writer.name("name").value(bodyParam.getName());
                writer.name("value").value(bodyParam.getValue());
                writer.endObject();
            }
            writer.endArray(); // end params array
            String requestBody = new String(requestBytes, StandardCharsets.UTF_8);
            writer.name("text").value(requestBody);
            writer.endObject(); // end postData object
        //}

        // Request Size
        writer.name("headersSize").value(Request.getHeaderSize(request));
        writer.name("bodySize").value(Request.getHeaderSize(request) - requestBytes.length);

        // End Request object
        writer.endObject();

        // Start Response object
        writer.name("response").beginObject();
        writer.name("status").value(Response.getResponseCode(response));
        writer.name("statusText").value(Response.getResponseStatus(response));
        writer.name("httpVersion").value(Response.getHTTPVersion(response));

        // Response Cookies
        writer.name("cookies").beginArray();
        if (Response.hasSetCookie(response)) {
            List<ICookie> cookies = getResponseCookies(responseBytes);
            for (ICookie cookie : cookies) {
                writer.beginObject();
                writer.name("name").value(cookie.getName());
                writer.name("value").value(cookie.getValue());
                writer.name("path").value(cookie.getPath());
                writer.name("domain").value(cookie.getDomain());
                writer.endObject();
            }
        }
        writer.endArray();

        // Response headers
        writer.name("headers").beginArray();
        Map<String, String> respHeaderMap = Response.getHeaders(response);
        for (Map.Entry<String,String> entry : respHeaderMap.entrySet()) {
            writer.beginObject();
            writer.name("name").value(entry.getKey());
            writer.name("value").value(entry.getValue());
            writer.endObject();
        }
        writer.endArray();

        // Response size
        writer.name("redirectURL").value("null");
        writer.name("headersSize").value(Response.getHeaderSize(response));
        writer.name("bodySize").value(responseBytes.length - Response.getHeaderSize(response));

        // Response content
        writer.name("content").beginObject();
        writer.name("size").value(responseBytes.length - Response.getHeaderSize(response));
        writer.name("mimeType").value("text/html");

        String responseBody = "";
        //if (responseBytes.length - Response.getHeaderSize(response) != 0){
            responseBody = new String(responseBytes, StandardCharsets.UTF_8);
        //}

        writer.name("text").value(responseBody);

        // End objects
        writer.endObject();
        writer.endObject();
        writer.name("cache").beginObject();
        writer.endObject();
        writer.name("timings").beginObject();
        writer.name("send").value(0);
        writer.name("wait").value(0);
        writer.name("receive").value(0);
        writer.endObject();
        writer.endObject();
        writer.endArray();
        writer.endObject();
        writer.endObject();
    }

    private List<IParameter> getRequestBodyParameters(byte[] request) {
        IRequestInfo tempAnalyzedReq = BurpExtender.getCallbacks().getHelpers().analyzeRequest(request);
        List<IParameter> params = tempAnalyzedReq.getParameters().stream()
                .filter(iParameter -> iParameter.getType() != IParameter.PARAM_COOKIE
                        && iParameter.getType() != IParameter.PARAM_URL)
                .collect(Collectors.toList());
        return params;
    }

    private List<ICookie> getResponseCookies(byte[] responseMessage) {
        IResponseInfo tempAnalyzedResp = BurpExtender.getCallbacks().getHelpers().analyzeResponse(responseMessage);
        return tempAnalyzedResp.getCookies();
    }

}
