package app.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Random;

public class Tag {

    @JsonProperty("id")
    private int id;
    @JsonProperty("colorName")
    private String colorName;
    @JsonProperty("name")
    private String name;
    @JsonProperty("evidenceCount")
    private int evidenceCount;

    public int getId(){ return id;};
    public String getName() { return name;}

    private enum Colors {
        blue,
        yellow,
        green,
        indigo,
        orange,
        pink,
        red,
        teal,
        vermilion,
        violet,
        lightBlue,
        lightYellow,
        lightGreen,
        lightIndigo,
        lightOrange,
        lightPink,
        lightRed,
        lightTeal,
        lightVermilion,
        lightViolet,
        disabledGray
    }
    private static final Colors[] colors = Colors.values();
    private static final int colorsSize = colors.length;
    private static final Random random = new Random();

    public static String getRandomColor() {
        return colors[random.nextInt(colorsSize)].toString();
    }

}
