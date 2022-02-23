package app.ui;

import app.model.Operation;

import javax.swing.*;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class EvidencePopup {

    public static String tags;

    public static String[] getUploadDetails(Operation[] operationList){

        JPanel evidencePanel = new JPanel(new GridLayout(0, 1));
        JComboBox<String> evidenceCampaignComboBox = new JComboBox<String>();
        evidenceCampaignComboBox.setBorder(new LineBorder(Color.BLACK));
        JLabel evidenceCampaignLabel = new JLabel("Select Campaign:");
        JLabel evidenceDescriptionLabel = new JLabel("Enter Description:");
        JTextArea evidenceDescriptionTextArea = new JTextArea();
        // BUG newline in this textarea
        evidenceDescriptionTextArea.setSize(evidenceDescriptionTextArea.getWidth(), evidenceDescriptionTextArea.getHeight()*2);
        evidenceDescriptionTextArea.setBorder(new LineBorder(Color.BLACK));

        for (Operation operation : operationList) {
            evidenceCampaignComboBox.addItem(operation.getName());
        }

        JButton evidenceAddTagsButton = new JButton("Add tags");
        evidenceAddTagsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    tags = TaggingPopup.getTags(evidenceCampaignComboBox.getSelectedItem().toString());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
        evidencePanel.add(evidenceCampaignLabel);
        evidencePanel.add(evidenceCampaignComboBox);
        evidencePanel.add(evidenceAddTagsButton);
        evidencePanel.add(evidenceDescriptionLabel);
        evidencePanel.add(evidenceDescriptionTextArea);

        int result = JOptionPane.showConfirmDialog(null, evidencePanel, "ASHIRT Evidence Upload",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            return new String[]{(String) evidenceCampaignComboBox.getSelectedItem(), evidenceDescriptionTextArea.getText(), tags};
        } else {
            return null;
        }
    }
}
