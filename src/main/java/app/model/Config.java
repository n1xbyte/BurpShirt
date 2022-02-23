package app.model;

// Use later to save/load config
public class Config {
    private String server;
    private String port;
    private String accessKey;
    private String secretKey;
    private boolean SSL;

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
}
