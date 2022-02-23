package app.helpers;

import app.model.ServerInfo;
import app.ui.MainUI;

import javax.swing.*;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class Output {
    private static final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    public static void output(String string) {
        Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
        String msg = sdf.format(cal.getTime()) + " | " + string;
        if (stdout == null) {
            System.out.println(msg);
        } else {
            stdout.println(msg);
        }
    }

    public static void outputError(String string) {
        Date cal = Calendar.getInstance(TimeZone.getDefault()).getTime();
        String msg = sdf.format(cal.getTime()) + " | ERROR: " + string;
        if (stderr == null) {
            System.err.println(msg);
        } else {
            stderr.println(msg);
        }
    }

    public static void writeResult(MainUI mainUI, String result){
        output(result);
        mainUI.resultsTextAreaEditor.append(result + "\n");
        mainUI.resultsTextAreaManage.append(result + "\n");
    }

    public static void writeError(MainUI mainUI, ServerInfo serverInfo, String result){
        outputError(result);
        mainUI.resultsTextAreaEditor.append("[-] Error: " + result + "\n");
        mainUI.resultsTextAreaManage.append("[-] Error: " + result + "\n");
        mainUI.connectionStatus.setText("Status: Error");
        serverInfo.setStatus(false);
    }

    public static void noConnectivity() {
        JOptionPane.showMessageDialog(null, "Connectivity not set up yet","BurpShirt",JOptionPane.INFORMATION_MESSAGE);
    }
}