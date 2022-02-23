package app.ui;

import app.BurpShirt;
import app.model.Tag;

import javax.swing.*;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class TaggingPopup {
    
    public static String getTags(String operation) throws IOException, NoSuchAlgorithmException, InvalidKeyException {

        // The mix of lists and arrays here makes me want to headbutt concrete, fix it
        JPanel tagPanel = new JPanel();
        JPanel tagTopPanel = new JPanel();
        JPanel tagBottomPanel = new JPanel();
        JSplitPane tagSplitPane = new JSplitPane();
        tagSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);


        tagBottomPanel.setLayout(new GridBagLayout());
        Tag[] tags = BurpShirt.getTags(operation);
        JCheckBox[] checkboxes = new JCheckBox[tags.length];

        JLabel tagNewLabel = new JLabel("New tag name:");
        JTextField tagNewTextField = new JTextField();
        tagNewTextField.setPreferredSize(new Dimension(250, tagNewTextField.getPreferredSize().height));
        tagNewTextField.setBorder(new LineBorder(Color.BLACK));
        JButton tagNewButton = new JButton("Create Tag");
        tagNewButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    BurpShirt.createTag(operation, tagNewTextField.getText());
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        if (tags.length == 0) {
            // Say empty
            JLabel emptyTagsLabel = new JLabel("No tags for " + operation);
            tagTopPanel.add(emptyTagsLabel);
        }
        else {
            // Create checkbox for each
            for (int i = 0; i < checkboxes.length; i++){
                checkboxes[i] = new JCheckBox(tags[i].getName());
                tagTopPanel.add(checkboxes[i]);
            }
        }
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = 1;
        tagBottomPanel.add(tagNewLabel, c);
        c.gridy = 2;
        tagBottomPanel.add(tagNewTextField, c);
        tagBottomPanel.add(tagNewButton, c);

        tagSplitPane.setTopComponent(tagTopPanel);
        tagSplitPane.setBottomComponent(tagBottomPanel);
        tagPanel.add(tagSplitPane);

        int result = JOptionPane.showConfirmDialog(null, tagPanel, "ASHIRT Tag Selection",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            List<Tag> selected = new ArrayList<>();
            for (JCheckBox checkbox : checkboxes) {
                if (checkbox.isSelected()) {
                    for (Tag tag: tags){
                        if (tag.getName().equals(checkbox.getText())){
                            selected.add(tag);
                        }
                    }
                }
            }
            StringBuilder tagsString = new StringBuilder();
            tagsString.append("[");
            for (int i =0; i < selected.size(); i++) {
                if (i == selected.size() - 1){
                    tagsString.append(selected.get(i).getId());
                }
                else {
                    tagsString.append(selected.get(i).getId() + ",");
                }
            }
            tagsString.append("]");
            return tagsString.toString();
        } else {
            return "[]";
        }
    }
}
