package app.ui;

import javax.swing.*;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionListener;

public class MainUI {
    public static final int textHeight = new JTextField().getPreferredSize().height;

    // Imports
    public JTabbedPane mainPanel;
    public ActionListener mainActionListener;

    // Panels
    public JPanel mainPanelEditor;
    public JPanel mainPanelManage;
    public JPanel leftPanelEditor;
    public JPanel rightPanelEditor;
    public JPanel leftPanelManage;
    public JPanel rightPanelManage;
    public JPanel leftBottomPanelEditor;
    public JPanel leftTopPanelEditor;
    public JPanel mainPanelConfig;
    public JSplitPane splitPaneEditor;
    public JSplitPane splitPaneManage;
    public JScrollPane scrollRequestAreaEditor;
    public JScrollPane scrollResponseAreaEditor;

    // Elements
    public JTextField serverTextField;
    public JTextField portTextField;
    public JTextField accessTextField;
    public JPasswordField secretTextField;
    public JTextField operationTextField;
    public JTextArea requestTextArea;
    public JTextArea responseTextArea;
    public JTextArea resultsTextAreaEditor;
    public JTextArea resultsTextAreaManage;
    public JLabel connectionStatus;
    public JLabel requestLabel;
    public JLabel responseLabel;
    public JLabel descriptionLabel;
    public JLabel serverLabel;
    public JLabel portLabel;
    public JLabel accessLabel;
    public JLabel secretLabel;
    public JLabel operationLabel;
    public JButton testConnectionButton;
    public JButton uploadEvidenceButton;
    public JButton createOperationButton;
    public GridBagConstraints c;

    public MainUI(JTabbedPane root, ActionListener actionListener) {
        mainPanel = root;
        mainActionListener = actionListener;
        createUI();
    }

    public void createUI(){
        createEditorTab();
        createManageTab();
        createConfigTab();
        addTabs();
    }

    public void createManageTab(){
        mainPanelManage = new JPanel();
        mainPanelManage.setLayout(new BoxLayout(mainPanelManage, BoxLayout.PAGE_AXIS));

        leftPanelManage = new JPanel();
        leftPanelManage.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        leftPanelManage.setLayout(new FlowLayout());

        operationLabel = new JLabel("Enter new operation name:");
        operationTextField = new JTextField();
        operationTextField.setPreferredSize(new Dimension(200,textHeight));
        createOperationButton = new JButton("Create Operation");
        createOperationButton.setActionCommand("createOperation");
        createOperationButton.addActionListener(mainActionListener);

        leftPanelManage.add(operationLabel, c);
        leftPanelManage.add(operationTextField, BorderLayout.CENTER);
        leftPanelManage.add(createOperationButton, c);

        rightPanelManage = new JPanel();
        rightPanelManage.setBorder(new TitledBorder(new EtchedBorder(), "Results"));
        resultsTextAreaManage = new JTextArea("[ ! ] Set configuration settings\n");
        resultsTextAreaManage.setSize(325, 100);
        resultsTextAreaManage.setLineWrap(true);
        resultsTextAreaManage.setEditable(false);

        rightPanelManage.add(resultsTextAreaManage);

        splitPaneManage = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        splitPaneManage.setLeftComponent(leftPanelManage);
        splitPaneManage.setRightComponent(rightPanelManage);
        splitPaneManage.setResizeWeight(0.75);
    }

    public void createEditorTab(){
        mainPanelEditor = new JPanel();
        mainPanelEditor.setLayout(new BoxLayout(mainPanelEditor, BoxLayout.PAGE_AXIS));

        // Create left panel
        leftPanelEditor = new JPanel();
        leftPanelEditor.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        leftPanelEditor.setLayout(new BoxLayout(leftPanelEditor, BoxLayout.Y_AXIS));
        leftTopPanelEditor = new JPanel();
        leftTopPanelEditor.setLayout(new BoxLayout(leftTopPanelEditor, BoxLayout.Y_AXIS));

        rightPanelEditor = new JPanel();
        splitPaneEditor = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // Left panel elements
        requestLabel = new JLabel("Request");
        responseLabel = new JLabel("Response");
        requestLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        responseLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        requestTextArea = new JTextArea();
        responseTextArea = new JTextArea();
        scrollRequestAreaEditor = new JScrollPane(requestTextArea);
        scrollRequestAreaEditor.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollRequestAreaEditor.setBorder(new LineBorder(Color.BLACK));
        requestTextArea.setLineWrap(true);
        scrollResponseAreaEditor = new JScrollPane(responseTextArea);
        scrollResponseAreaEditor.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollResponseAreaEditor.setBorder(new LineBorder(Color.BLACK));
        responseTextArea.setLineWrap(true);

        // Left panel bottom
        leftBottomPanelEditor = new JPanel();
        leftBottomPanelEditor.setLayout(new BoxLayout(leftBottomPanelEditor, BoxLayout.LINE_AXIS));
        leftBottomPanelEditor.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
        uploadEvidenceButton = new JButton("Send to ASHIRT");
        uploadEvidenceButton.setActionCommand("uploadEvidence");
        uploadEvidenceButton.addActionListener(mainActionListener);

        //Right panel
        rightPanelEditor.setBorder(new TitledBorder(new EtchedBorder(), "Results"));
        resultsTextAreaEditor = new JTextArea("[ ! ] Set configuration settings\n");
        resultsTextAreaEditor.setSize(325, 100);
        resultsTextAreaEditor.setLineWrap(true);
        resultsTextAreaEditor.setEditable(false);
        rightPanelEditor.add(resultsTextAreaEditor);

        leftTopPanelEditor.add(requestLabel);
        c = new GridBagConstraints();
        c.weighty = 1;
        c.anchor = GridBagConstraints.SOUTH;
        leftTopPanelEditor.add(scrollRequestAreaEditor, c);
        leftTopPanelEditor.add(responseLabel);
        leftTopPanelEditor.add(scrollResponseAreaEditor, c);
        leftBottomPanelEditor.add(uploadEvidenceButton, c);
        leftPanelEditor.add(leftTopPanelEditor);
        leftPanelEditor.add(leftBottomPanelEditor);
        splitPaneEditor.setLeftComponent(leftPanelEditor);
        splitPaneEditor.setRightComponent(rightPanelEditor);
    }

    public void createConfigTab(){

        mainPanelConfig = new JPanel();

        mainPanelConfig.setLayout(new GridBagLayout());
        mainPanelConfig.setPreferredSize(new Dimension(500, textHeight * 8));
        mainPanelConfig.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanelConfig.setBorder(BorderFactory.createTitledBorder("ASHIRT Configuration"));

        c = new GridBagConstraints();

        serverTextField = new JTextField();
        portTextField = new JTextField();
        accessTextField = new JTextField();
        secretTextField = new JPasswordField();

        serverTextField.setPreferredSize(new Dimension(250, textHeight));
        portTextField.setPreferredSize(new Dimension(250, textHeight));
        accessTextField.setPreferredSize(new Dimension(250, textHeight));
        secretTextField.setPreferredSize(new Dimension(250, textHeight));


        descriptionLabel = new JLabel("Specify connection parameters");
        serverLabel = new JLabel("Server: ");
        portLabel = new JLabel("Port: ");
        accessLabel = new JLabel("Access Key: ");
        secretLabel = new JLabel("Secret Key: ");
        connectionStatus = new JLabel("Status: Not connected");

        testConnectionButton = new JButton("Connect");
        testConnectionButton.setActionCommand("checkConnection");
        testConnectionButton.addActionListener(mainActionListener);

        c.anchor = GridBagConstraints.NORTHWEST;
        c.gridx = 0;
        c.gridy = 1;
        mainPanelConfig.add(serverLabel, c);
        c.gridy = 2;
        mainPanelConfig.add(portLabel, c);
        c.gridy = 3;
        mainPanelConfig.add(accessLabel, c);
        c.gridy = 4;
        mainPanelConfig.add(secretLabel, c);

        c.anchor = GridBagConstraints.EAST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 1;
        c.gridy = 1;
        mainPanelConfig.add(serverTextField, c);
        c.gridy = 2;
        mainPanelConfig.add(portTextField, c);
        c.gridy = 3;
        mainPanelConfig.add(accessTextField, c);
        c.gridy = 4;
        mainPanelConfig.add(secretTextField, c);
        c.gridy = 5;
        mainPanelConfig.add(testConnectionButton, c);
        c.gridy = 6;
        mainPanelConfig.add(connectionStatus, c);

        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 0;
        mainPanelConfig.add(descriptionLabel, c);

        Dimension buttonDimension = new Dimension(200, new JTextField().getPreferredSize().height);
        testConnectionButton.setPreferredSize(buttonDimension);
        testConnectionButton.setMaximumSize(buttonDimension);
        testConnectionButton.setMinimumSize(buttonDimension);
    }

    public void addTabs(){
        mainPanelEditor.add(splitPaneEditor);
        splitPaneEditor.setResizeWeight(0.75);
        mainPanelManage.add(splitPaneManage);
        splitPaneManage.setResizeWeight(0.75);
        mainPanel.addTab("Editor", mainPanelEditor);
        mainPanel.addTab("Manage", mainPanelManage);
        mainPanel.addTab("Configuration", mainPanelConfig);
    }
}
