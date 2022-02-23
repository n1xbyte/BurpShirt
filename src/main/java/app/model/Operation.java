package app.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Operation {
    @JsonProperty("slug")
    private String slug;
    @JsonProperty("name")
    private String name;
    @JsonProperty("numUsers")
    private int numUsers;
    @JsonProperty("status")
    private int status;
    @JsonProperty("id")
    private int id;

    public String getSlug() {
        return slug;
    }
    public String getName() {
        return name;
    }
    public int getID() {
        return id;
    }
}