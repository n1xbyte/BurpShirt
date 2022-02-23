package app.model;

public class ServerInfo {
    private String server;
    private String port;
    private String accessKey;
    private String secretKey;
    private boolean SSL;
    private boolean status;

    public String getServer() {
        return this.server;
    }
    public void setServer(String server) {
        this.server = server;
    }
    public String getPort() {
        return this.port;
    }
    public void setPort(String port) {
        this.port = port;
    }
    public String getAccessKey() {
        return this.accessKey;
    }
    public void setAccessKey(String accessKey) {
        this.accessKey = accessKey;
    }
    public String getSecretKey() {
        return this.secretKey;
    }
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
    public boolean getSSL() {
        return this.SSL;
    }
    public void setSSL(boolean SSL) {
        this.SSL = SSL;
    }
    public boolean getStatus() {
        return this.status;
    }
    public void setStatus(boolean status) {
        this.status = status;
    }

    public String getServerURL() {
        String serverPath = null;
        if (SSL){
            serverPath = "https://" + server + ":" + port;
        }
        else{
            serverPath = "http://" + server + ":" + port;
        }
        return serverPath;
    }
}