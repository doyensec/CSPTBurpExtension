package com.doyensec.ClientSidePathTraversal;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;

public class ClientSidePathTraversalForm {
    private JPanel contentPanel;
    private JButton scanButton;
    private JTable resultSourceTable;
    private JPanel scanOption;
    private JTextField sourceScope;
    private JTextField sinkScope;
    private JTable resultSinkTable;
    private JList<String> resultsList;
    private JPanel sinkOption;
    private JCheckBox POSTCheckBox;
    private JCheckBox DELETECheckBox;
    private JCheckBox PUTCheckBox;
    private JCheckBox PATCHCheckBox;
    private JCheckBox GETCheckBox;
    private JButton exportSourcesWithCanaryButton;
    private JTextField canaryTokenValue;
    private JButton copyCanaryValueButton;
    private JButton generateNewCanaryValueButton;
    private JPanel canaryConf;
    private JProgressBar progressBarSource;
    private JProgressBar progressBarReflection;
    private final DefaultTableModel resultSourceTableModel = new DefaultTableModel(new String[]{"Param Name", "URL"}, 0);
    private final DefaultTableModel resultSinkTableModel = new DefaultTableModel(new String[]{"Method", "URL"}, 0);
    private ClientSidePathTraversal cspt;
    private CSPTScannerTask currentTask = null;

    public CSPTScannerTask getCurrentTask() {
        return currentTask;
    }
    boolean scanInProgress = false;

    public ClientSidePathTraversalForm(ClientSidePathTraversal cspt) {

        $$$setupUI$$$();

        this.cspt = cspt;
        // Placeholder to not have to handle null values
        this.currentTask = new CSPTScannerTask(cspt);

        // Set up buttons
        scanButton.addActionListener(e -> {
            if (!scanInProgress) {
                // Start scan

                saveConfiguration(cspt);

                this.reset();

                this.currentTask = new CSPTScannerTask(cspt);
                this.currentTask.execute();
                scanButton.setText("Cancel");
                this.scanInProgress = true;
            } else {
                // Cancel scan
                this.currentTask.cancel(true);
                this.currentTask = new CSPTScannerTask(cspt);
                this.reset();
                scanButton.setText("Scan");
                this.scanInProgress = false;
            }
        });

        exportSourcesWithCanaryButton.addActionListener(e -> {
            List<String> sourceWithCanary = this.getCurrentTask().getAllSourcesWithCanary();
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new StringSelection(String.join("\n", sourceWithCanary)), null);
        });

        generateNewCanaryValueButton.addActionListener(e -> {
            cspt.setCanary(cspt.generateCanaryToken());
            canaryTokenValue.setText(cspt.getCanary());
        });

        copyCanaryValueButton.addActionListener(e ->
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(cspt.getCanary()), null)
        );

        loadConfiguration(cspt);

        // Init results table
        resultSourceTable.setModel(resultSourceTableModel);
        resultSourceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultSinkTable.setModel(resultSinkTableModel);
        resultSinkTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // TODO: check if it's ok to only initialize these once
        createContextualMenusSources(cspt);
        createContextualMenusSinks(cspt);
    }

    public void reset() {
        // Reset progress bars
        progressBarSource.setIndeterminate(false);
        progressBarSource.setValue(0);
        progressBarReflection.setIndeterminate(false);
        progressBarReflection.setValue(0);

        // Reset tables
        for (ListSelectionListener listSelectionListener : resultsList.getListSelectionListeners()) {
            resultsList.removeListSelectionListener(listSelectionListener);
        }
        resultsList.setListData(new String[0]);
        resultSinkTableModel.setRowCount(0);
        resultSourceTableModel.setRowCount(0);
    }

    public void loadConfiguration(ClientSidePathTraversal cspt) {
        sourceScope.setText(cspt.getSourceScope());
        sinkScope.setText(cspt.getSinkScope());

        POSTCheckBox.setSelected(false);
        PUTCheckBox.setSelected(false);
        PATCHCheckBox.setSelected(false);
        DELETECheckBox.setSelected(false);
        GETCheckBox.setSelected(false);

        canaryTokenValue.setText(cspt.getCanary());

        for (String httpMethod : cspt.getSinkHTTPMethods()) {
            switch (httpMethod) {
                case "POST" -> POSTCheckBox.setSelected(true);
                case "PUT" -> PUTCheckBox.setSelected(true);
                case "PATCH" -> PATCHCheckBox.setSelected(true);
                case "DELETE" -> DELETECheckBox.setSelected(true);
                case "GET" -> GETCheckBox.setSelected(true);
            }
        }
    }

    public void saveConfiguration(ClientSidePathTraversal cspt) {
        cspt.setSourceScope(sourceScope.getText());
        cspt.setSinkScope(sinkScope.getText());

        List<String> sinkHTTPMethods = new ArrayList<>();

        if (POSTCheckBox.isSelected()) {
            sinkHTTPMethods.add(POSTCheckBox.getText());
        }
        if (PUTCheckBox.isSelected()) {
            sinkHTTPMethods.add(PUTCheckBox.getText());
        }
        if (PATCHCheckBox.isSelected()) {
            sinkHTTPMethods.add(PATCHCheckBox.getText());
        }
        if (DELETECheckBox.isSelected()) {
            sinkHTTPMethods.add(DELETECheckBox.getText());
        }
        if (GETCheckBox.isSelected()) {
            sinkHTTPMethods.add(GETCheckBox.getText());
        }

        cspt.setCanary(canaryTokenValue.getText());
        cspt.setSinkHTTPMethods(sinkHTTPMethods);
    }

    public void setProgressSource(int percent) {
        progressBarSource.setValue(percent);
    }

    public void initProgressSource() {
        progressBarSource.setValue(0);
        progressBarSource.setIndeterminate(true);
    }

    public void finishProgressSource() {
        progressBarSource.setIndeterminate(false);
        progressBarSource.setValue(100);
    }

    public void setProgressReflection(int percent) {
        progressBarReflection.setValue(percent);
    }

    public void initProgressReflection() {
        progressBarReflection.setValue(0);
        progressBarReflection.setIndeterminate(true);
    }

    public void finishProgressReflection() {
        progressBarReflection.setIndeterminate(false);
        progressBarReflection.setValue(100);
    }

    public void displayResults(
            CSPTScannerTask task
    ) {
        if (task != this.currentTask) {
            // A new scan was probably started before this one could finish, ignore
            return;
        }

        var pathLookup = task.getPathLookup();

        // Not removing the selection listener from the list will hang the extension

        for (ListSelectionListener listSelectionListener : resultsList.getListSelectionListeners()) {
            resultsList.removeListSelectionListener(listSelectionListener);
        }

        resultsList.setListData(pathLookup.keySet().toArray(new String[0]));

        resultsList.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            displaySourcesAndSinks(this.currentTask.getParamValueLookup(), this.currentTask.getPathLookup(), resultsList.getSelectedValue());
        });

        this.scanInProgress = false;
        this.scanButton.setText("Scan");
    }

    public void displaySourcesAndSinks(
            Map<String, Set<PotentialSource>> paramValueLookup,
            Map<String, Set<PotentialSink>> pathLookup,
            String paramValue
    ) {
        displaySources(paramValueLookup, paramValue);
        displaySinks(pathLookup, paramValue);

        resultSourceTable.updateUI();
        resultSinkTable.updateUI();
    }

    public void displaySources(Map<String, Set<PotentialSource>> paramValueLookup, String paramValue) {
        resultSourceTableModel.setRowCount(0); // Clear the table
        for (PotentialSource source : paramValueLookup.get(paramValue)) {
            resultSourceTableModel.addRow(new String[]{source.paramName, source.sourceURL});
        }
    }

    public void displaySinks(Map<String, Set<PotentialSink>> pathLookup, String paramValue) {
        resultSinkTableModel.setRowCount(0); // Clear the table
        for (PotentialSink sink : pathLookup.get(paramValue)) {
            resultSinkTableModel.addRow(new String[]{sink.method, sink.url});
        }
    }

    private void createContextualMenusSinks(ClientSidePathTraversal cspt) {
        final JPopupMenu popupMenuSinkTable = new JPopupMenu();
        JMenuItem findLaxSinks = new JMenuItem("Send sinks (host/method) to Organizer");

        resultSinkTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                int r = resultSinkTable.rowAtPoint(e.getPoint());
                if (r >= 0 && r < resultSinkTable.getRowCount()) {
                    resultSinkTable.setRowSelectionInterval(r, r);
                } else {
                    resultSinkTable.clearSelection();
                }

                int rowindex = resultSinkTable.getSelectedRow();
                if (rowindex < 0)
                    return;
                if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                    popupMenuSinkTable.show(e.getComponent(), e.getX(), e.getY());
                }

            }
        });
        findLaxSinks.addActionListener(e -> {
            String method = resultSinkTable.getValueAt(resultSinkTable.getSelectedRow(), 0).toString();
            String url = resultSinkTable.getValueAt(resultSinkTable.getSelectedRow(), 1).toString();

            // Send sinks to the organizer
            cspt.getExploitableSinks(method, HttpRequest.httpRequestFromUrl(url).httpService().host());
        });
        popupMenuSinkTable.add(findLaxSinks);
        resultSinkTable.setComponentPopupMenu(popupMenuSinkTable);
    }

    private void createContextualMenusSources(ClientSidePathTraversal cspt) {
        final JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyURLWithCanary = new JMenuItem("Copy URL With Canary");
        JMenuItem copyURL = new JMenuItem("Copy URL");
        JMenuItem falsePositiveParam = new JMenuItem("Set Parameter as a false positive");
        JMenuItem falsePositiveParamURL = new JMenuItem("Set Parameter and URL as a false positive");

        resultSourceTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                int r = resultSourceTable.rowAtPoint(e.getPoint());
                if (r >= 0 && r < resultSourceTable.getRowCount()) {
                    resultSourceTable.setRowSelectionInterval(r, r);
                } else {
                    resultSourceTable.clearSelection();
                }

                int rowindex = resultSourceTable.getSelectedRow();
                if (rowindex < 0)
                    return;
                if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        copyURLWithCanary.addActionListener(e -> {
            String url = resultSourceTable.getValueAt(resultSourceTable.getSelectedRow(), 1).toString();
            String param = resultSourceTable.getValueAt(resultSourceTable.getSelectedRow(), 0).toString();
            String urlWithCanary = cspt.replaceParamWithCanary(param, url);

            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(urlWithCanary), null);
        });
        popupMenu.add(copyURLWithCanary);

        copyURL.addActionListener(e -> {
            String url = resultSourceTable.getValueAt(resultSourceTable.getSelectedRow(), 1).toString();
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
        });
        popupMenu.add(copyURL);

        falsePositiveParam.addActionListener(e -> {
            cspt.addFalsePositive(resultSourceTable.getValueAt(resultSourceTable.getSelectedRow(), 0).toString(), ".*");
        });
        popupMenu.add(falsePositiveParam);

        falsePositiveParamURL.addActionListener(e -> {
            cspt.addFalsePositive(resultSourceTable.getValueAt(resultSourceTable.getSelectedRow(), 0).toString(),
                    Pattern.quote(resultSourceTable.getValueAt(resultSourceTable.getSelectedRow(), 1).toString()));
        });
        popupMenu.add(falsePositiveParamURL);
        resultSourceTable.setComponentPopupMenu(popupMenu);
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        contentPanel = new JPanel();
        contentPanel.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new BorderLayout(0, 0));
        contentPanel.add(panel1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 4, new Insets(4, 6, 4, 6), -1, -1));
        panel1.add(panel2, BorderLayout.NORTH);
        scanOption = new JPanel();
        scanOption.setLayout(new GridLayoutManager(2, 2, new Insets(0, 2, 0, 2), -1, 10));
        panel2.add(scanOption, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        sourceScope = new JTextField();
        sourceScope.setEditable(true);
        sourceScope.setText(".*");
        scanOption.add(sourceScope, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        sinkScope = new JTextField();
        sinkScope.setText(".*");
        scanOption.add(sinkScope, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setHorizontalAlignment(4);
        label1.setText("Source scope (RegExp)");
        scanOption.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setHorizontalAlignment(4);
        label2.setText("Sink scope (RegExp)");
        scanOption.add(label2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(129, 8), null, 0, false));
        sinkOption = new JPanel();
        sinkOption.setLayout(new GridLayoutManager(3, 2, new Insets(0, 2, 0, 2), -1, -1));
        panel2.add(sinkOption, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        POSTCheckBox = new JCheckBox();
        POSTCheckBox.setEnabled(true);
        POSTCheckBox.setSelected(true);
        POSTCheckBox.setText("POST");
        sinkOption.add(POSTCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        PATCHCheckBox = new JCheckBox();
        PATCHCheckBox.setSelected(true);
        PATCHCheckBox.setText("PATCH");
        sinkOption.add(PATCHCheckBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        DELETECheckBox = new JCheckBox();
        DELETECheckBox.setSelected(true);
        DELETECheckBox.setText("DELETE");
        sinkOption.add(DELETECheckBox, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        PUTCheckBox = new JCheckBox();
        PUTCheckBox.setSelected(true);
        PUTCheckBox.setText("PUT");
        sinkOption.add(PUTCheckBox, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        GETCheckBox = new JCheckBox();
        GETCheckBox.setEnabled(true);
        GETCheckBox.setSelected(true);
        GETCheckBox.setText("GET");
        sinkOption.add(GETCheckBox, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        canaryConf = new JPanel();
        canaryConf.setLayout(new GridLayoutManager(2, 2, new Insets(0, 2, 0, 2), -1, -1));
        canaryConf.setAlignmentX(0.5f);
        panel2.add(canaryConf, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        canaryTokenValue = new JTextField();
        canaryConf.add(canaryTokenValue, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Canary Token : ");
        canaryConf.add(label3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        copyCanaryValueButton = new JButton();
        copyCanaryValueButton.setText("Copy canary value");
        canaryConf.add(copyCanaryValueButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_SOUTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        generateNewCanaryValueButton = new JButton();
        generateNewCanaryValueButton.setText("Regenerate canary token");
        canaryConf.add(generateNewCanaryValueButton, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_SOUTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(3, 3, new Insets(0, 2, 0, 2), -1, -1));
        panel2.add(panel3, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        scanButton = new JButton();
        scanButton.setText("Scan");
        panel3.add(scanButton, new GridConstraints(0, 0, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        exportSourcesWithCanaryButton = new JButton();
        exportSourcesWithCanaryButton.setText("Export Sources With Canary");
        panel3.add(exportSourcesWithCanaryButton, new GridConstraints(2, 0, 1, 3, GridConstraints.ANCHOR_SOUTH, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        progressBarSource = new JProgressBar();
        progressBarSource.setStringPainted(true);
        panel3.add(progressBarSource, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        progressBarReflection = new JProgressBar();
        progressBarReflection.setStringPainted(true);
        panel3.add(progressBarReflection, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Reflection scan");
        panel3.add(label4, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Source listing");
        panel3.add(label5, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 1, new Insets(4, 4, 4, 4), -1, -1));
        panel1.add(panel4, BorderLayout.CENTER);
        final JSplitPane splitPane1 = new JSplitPane();
        panel4.add(splitPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        splitPane1.setLeftComponent(scrollPane1);
        scrollPane1.setBorder(BorderFactory.createTitledBorder(null, "Reflected Values", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        resultsList = new JList();
        final DefaultListModel defaultListModel1 = new DefaultListModel();
        resultsList.setModel(defaultListModel1);
        scrollPane1.setViewportView(resultsList);
        final JSplitPane splitPane2 = new JSplitPane();
        splitPane2.setEnabled(true);
        splitPane2.setOrientation(0);
        splitPane1.setRightComponent(splitPane2);
        final JScrollPane scrollPane2 = new JScrollPane();
        scrollPane2.setAutoscrolls(false);
        scrollPane2.setHorizontalScrollBarPolicy(30);
        scrollPane2.setMinimumSize(new Dimension(30, 150));
        splitPane2.setRightComponent(scrollPane2);
        scrollPane2.setBorder(BorderFactory.createTitledBorder(null, "Sinks", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        resultSinkTable = new JTable();
        scrollPane2.setViewportView(resultSinkTable);
        final JScrollPane scrollPane3 = new JScrollPane();
        scrollPane3.setHorizontalScrollBarPolicy(30);
        scrollPane3.setMinimumSize(new Dimension(30, 150));
        splitPane2.setLeftComponent(scrollPane3);
        scrollPane3.setBorder(BorderFactory.createTitledBorder(null, "Sources", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        resultSourceTable = new JTable();
        resultSourceTable.setAutoCreateRowSorter(true);
        resultSourceTable.setAutoResizeMode(4);
        resultSourceTable.setColumnSelectionAllowed(false);
        resultSourceTable.setEnabled(true);
        resultSourceTable.setVisible(true);
        scrollPane3.setViewportView(resultSourceTable);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return contentPanel;
    }

}
