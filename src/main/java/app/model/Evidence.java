package app.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Evidence {
    @JsonProperty("uuid")
    private String uuid;
    @JsonProperty("description")
    private String description;
    @JsonProperty("occurredAt")
    private String occuredAt;
    @JsonProperty("operator")
    private Operator operator;
    @JsonProperty("tags")
    private String tags;
    @JsonProperty("contentType")
    private String contentType;

    public String getUUID(){
        return uuid;
    }
}
