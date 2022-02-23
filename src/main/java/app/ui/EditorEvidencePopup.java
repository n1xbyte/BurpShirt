package app.ui;

import javax.swing.*;
import javax.swing.border.LineBorder;
import java.awt.*;

public class EditorEvidencePopup {
    public static String[] getUploadDetails(){

        JPanel evidencePanel = new JPanel(new GridLayout(0, 1));
        JComboBox<String> evidenceOperationComboBox = new JComboBox<String>();
        evidenceOperationComboBox.setBorder(new LineBorder(Color.BLACK));
        JLabel evidenceServerLabel = new JLabel("Enter Server:");
        JLabel evidencePortLabel = new JLabel("Enter Port:");
        JCheckBox evidenceSSLCheckBox = new JCheckBox("SSL?");
        JTextArea evidenceServerTextArea = new JTextArea();
        JTextArea evidencePortTextArea = new JTextArea();
        evidenceServerTextArea.setBorder(new LineBorder(Color.BLACK));
        evidencePortTextArea.setBorder(new LineBorder(Color.BLACK));

        evidencePanel.add(evidenceServerLabel);
        evidencePanel.add(evidenceServerTextArea);
        evidencePanel.add(evidencePortLabel);
        evidencePanel.add(evidencePortTextArea);
        evidencePanel.add(evidenceSSLCheckBox);
        int result = JOptionPane.showConfirmDialog(null, evidencePanel, "ASHIRT Evidence Upload",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            String[] returnValues = new String[4];
            returnValues[0] = evidenceServerTextArea.getText().trim();
            if (returnValues[0].startsWith("https://")) {
                returnValues[0] = returnValues[0].substring(8);

            } else if (returnValues[0].startsWith("http://")) {
                returnValues[0] = returnValues[0].substring(7);
            }
            if (isStringInt(evidencePortTextArea.getText())) {
                returnValues[1] = evidencePortTextArea.getText().trim();
            }
            else {
                JOptionPane.showMessageDialog(null, "Submit an integer in Port field","BurpShirt",JOptionPane.INFORMATION_MESSAGE);
                getUploadDetails();
            }
            if (evidenceSSLCheckBox.isSelected()){
                returnValues[2] = "https";
            }
            else {
                returnValues[2] = "http";
            }
            return returnValues;
        } else {
            return null;
        }
    }
    public static boolean isStringInt(String s)
    {
        try
        {
            Integer.parseInt(s.trim());
            return true;
        } catch (NumberFormatException ex)
        {
            return false;
        }
    }
}
