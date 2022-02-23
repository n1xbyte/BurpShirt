package app.model;

import com.fasterxml.jackson.annotation.JsonProperty;

class Operator {
    @JsonProperty("firstName")
    private String firstName;
    @JsonProperty("lastName")
    private String lastName;
    @JsonProperty("slug")
    private String slug;
}