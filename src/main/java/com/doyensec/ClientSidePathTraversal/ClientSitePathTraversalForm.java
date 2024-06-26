package com.doyensec.ClientSidePathTraversal;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import burp.api.montoya.http.message.requests.HttpRequest;

public class ClientSitePathTraversalForm {
    private JPanel panel1;
    private JButton scanButton;
    private JTable resultSourceTable;
    private JPanel scanOption;
    private JTextField sourceScope;
    private JTextField sinkScope;
    private JTable resultSinkTable;
    private JList resultsList;
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

    public ClientSitePathTraversalForm(ClientSidePathTraversal cspt) {

        $$$setupUI$$$();
        scanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                // Save Storage
                saveConfiguration(cspt);
                progressBarSource.setValue(0);

                CSPTScannerTask csptScannerTask = new CSPTScannerTask(cspt);
                csptScannerTask.execute();

            }
        });
        exportSourcesWithCanaryButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<String> sourceWithCanary = cspt.getAllSourcesWithCanary();
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(sourceWithCanary.stream().collect(Collectors.joining("\n"))), null);
            }
        });

        generateNewCanaryValueButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cspt.setCanary(cspt.generateCanaryToken());
                canaryTokenValue.setText(cspt.getCanary());
            }
        });

        copyCanaryValueButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(cspt.getCanary()),
                        null);
            }
        });

        loadConfiguration(cspt);

        // Init results table
        resultSourceTable.setModel(new DefaultTableModel(null, new String[] { "Param Name", "URL" }));
        resultSinkTable.setModel(new DefaultTableModel(null, new String[] { "Method", "URL" }));
    }

    public void saveConfiguration(ClientSidePathTraversal cspt) {
        cspt.setSourceScope(sourceScope.getText());
        cspt.setSinkScope(sinkScope.getText());

        List<String> sinkHTTPMethods = new ArrayList<String>();

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
        progressBarReflection.setIndeterminate(true);
    }

    public void finishProgressReflection() {
        progressBarReflection.setIndeterminate(false);
        progressBarReflection.setValue(100);
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
            case "POST":
                POSTCheckBox.setSelected(true);
                break;
            case "PUT":
                PUTCheckBox.setSelected(true);
                break;
            case "PATCH":
                PATCHCheckBox.setSelected(true);
                break;
            case "DELETE":
                DELETECheckBox.setSelected(true);
                break;
            case "GET":
                GETCheckBox.setSelected(true);
                break;
            }

        }

    }

    public void displayResults(Map<String, Set<PotentialSource>> paramValueLookup,
            Map<String, Set<PotentialSink>> pathLookup, ClientSidePathTraversal cspt) {

        DefaultListModel resultsListModel = new DefaultListModel();

        for (String paramValue : pathLookup.keySet()) {
            resultsListModel.addElement(paramValue);
        }

        if (resultsList.getListSelectionListeners() != null && resultsList.getListSelectionListeners().length > 0) {
            resultsList.removeListSelectionListener(resultsList.getListSelectionListeners()[0]);
        }

        resultsList.setModel(resultsListModel);

        resultsList.addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    displaySourcesAndSinks(paramValueLookup, pathLookup, resultsList.getSelectedValue().toString());
                    createContextualMenusSources(cspt);
                    createContextualMenusSinks(cspt);

                }
            }

        });
    }

    public void displaySourcesAndSinks(Map<String, Set<PotentialSource>> paramValueLookup,
            Map<String, Set<PotentialSink>> pathLookup, String paramValue) {
        displaySources(paramValueLookup, paramValue);
        displaySinks(pathLookup, paramValue);

        resultSourceTable.updateUI();
        resultSinkTable.updateUI();

    }

    public void displaySources(Map<String, Set<PotentialSource>> paramValueLookup, String paramValue) {
        Object[][] arr = new Object[paramValueLookup.get(paramValue).size()][2];

        int i = 0;

        for (PotentialSource source : paramValueLookup.get(paramValue)) {
            // param Value at the position 0
            arr[i][0] = source.paramName;
            arr[i][1] = source.sourceURL;
            i++;
        }

        resultSourceTable.setModel(new DefaultTableModel(arr, new String[] { "Param Name", "URL" }));
    }

    public void displaySinks(Map<String, Set<PotentialSink>> pathLookup, String paramValue) {
        Object[][] arr = new Object[pathLookup.get(paramValue).size()][2];

        int i = 0;

        for (PotentialSink sink : pathLookup.get(paramValue)) {
            arr[i][0] = sink.method;
            arr[i][1] = sink.url;
            i++;
        }

        resultSinkTable.setModel(new DefaultTableModel(arr, new String[] { "Method", "URL" }));

    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return panel1;
    }

    private void createContextualMenusSinks(ClientSidePathTraversal cspt) {
        final JPopupMenu popupMenuSinkTable = new JPopupMenu();
        JMenuItem findLaxSinks = new JMenuItem("Send sinks(host/method) To Organizer");

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
        findLaxSinks.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                Component c = (Component) e.getSource();
                JPopupMenu popup = (JPopupMenu) c.getParent();
                JTable table = (JTable) popup.getInvoker();

                String method = table.getValueAt(table.getSelectedRow(), 0).toString();
                String url = table.getValueAt(table.getSelectedRow(), 1).toString();

                // Send sinks to the organizer
                cspt.getExploitableSink(method, HttpRequest.httpRequestFromUrl(url).httpService().host());
            }
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

        copyURLWithCanary.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                Component c = (Component) e.getSource();
                JPopupMenu popup = (JPopupMenu) c.getParent();
                JTable table = (JTable) popup.getInvoker();

                String url = table.getValueAt(table.getSelectedRow(), 1).toString();
                String param = table.getValueAt(table.getSelectedRow(), 0).toString();
                String urlWithCanary = cspt.replaceParamWithCanary(param, url);

                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(urlWithCanary), null);

            }
        });
        popupMenu.add(copyURLWithCanary);

        copyURL.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                Component c = (Component) e.getSource();
                JPopupMenu popup = (JPopupMenu) c.getParent();
                JTable table = (JTable) popup.getInvoker();

                String url = table.getValueAt(table.getSelectedRow(), 1).toString();
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
            }
        });
        popupMenu.add(copyURL);

        falsePositiveParam.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                Component c = (Component) e.getSource();
                JPopupMenu popup = (JPopupMenu) c.getParent();
                JTable table = (JTable) popup.getInvoker();
                cspt.addFalsePositive(table.getValueAt(table.getSelectedRow(), 0).toString(), ".*");
            }
        });
        popupMenu.add(falsePositiveParam);

        falsePositiveParamURL.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                Component c = (Component) e.getSource();
                JPopupMenu popup = (JPopupMenu) c.getParent();
                JTable table = (JTable) popup.getInvoker();
                cspt.addFalsePositive(table.getValueAt(table.getSelectedRow(), 0).toString(),
                        Pattern.quote(table.getValueAt(table.getSelectedRow(), 1).toString()));
            }
        });
        popupMenu.add(falsePositiveParamURL);
        resultSourceTable.setComponentPopupMenu(popupMenu);
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer >>> IMPORTANT!! <<< DO NOT
     * edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        final JSplitPane splitPane1 = new JSplitPane();
        splitPane1.setOrientation(0);
        panel1.add(splitPane1,
                new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null, new Dimension(200, 200), null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 4, new Insets(0, 0, 0, 0), -1, -1));
        splitPane1.setLeftComponent(panel2);
        scanOption = new JPanel();
        scanOption.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(scanOption,
                new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null, null, null, 0, false));
        sourceScope = new JTextField();
        sourceScope.setText(".*");
        scanOption.add(sourceScope,
                new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1),
                        null, 0, false));
        sinkScope = new JTextField();
        sinkScope.setText(".*");
        scanOption.add(sinkScope,
                new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1),
                        null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Source scope(Regexp)");
        scanOption.add(label1,
                new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Sink scope(Regexp)");
        scanOption.add(label2,
                new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sinkOption = new JPanel();
        sinkOption.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(sinkOption,
                new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null, null, null, 0, false));
        POSTCheckBox = new JCheckBox();
        POSTCheckBox.setEnabled(true);
        POSTCheckBox.setSelected(true);
        POSTCheckBox.setText("POST");
        sinkOption.add(POSTCheckBox,
                new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        PATCHCheckBox = new JCheckBox();
        PATCHCheckBox.setSelected(true);
        PATCHCheckBox.setText("PATCH");
        sinkOption.add(PATCHCheckBox,
                new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        DELETECheckBox = new JCheckBox();
        DELETECheckBox.setSelected(true);
        DELETECheckBox.setText("DELETE");
        sinkOption.add(DELETECheckBox,
                new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        PUTCheckBox = new JCheckBox();
        PUTCheckBox.setSelected(true);
        PUTCheckBox.setText("PUT");
        sinkOption.add(PUTCheckBox,
                new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        GETCheckBox = new JCheckBox();
        GETCheckBox.setEnabled(true);
        GETCheckBox.setSelected(true);
        GETCheckBox.setText("GET");
        sinkOption.add(GETCheckBox,
                new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        canaryConf = new JPanel();
        canaryConf.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
        canaryConf.setAlignmentX(0.5f);
        panel2.add(canaryConf,
                new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null, null, null, 0, false));
        canaryTokenValue = new JTextField();
        canaryConf.add(canaryTokenValue,
                new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1),
                        null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Canary Token : ");
        canaryConf.add(label3,
                new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        generateNewCanaryValueButton = new JButton();
        generateNewCanaryValueButton.setText("Regenerate canary token");
        canaryConf.add(generateNewCanaryValueButton,
                new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        copyCanaryValueButton = new JButton();
        copyCanaryValueButton.setText("Copy canary value");
        canaryConf.add(copyCanaryValueButton,
                new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3,
                new com.intellij.uiDesigner.core.GridConstraints(0, 3, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null, null, null, 0, false));
        scanButton = new JButton();
        scanButton.setText("Scan");
        panel3.add(scanButton,
                new com.intellij.uiDesigner.core.GridConstraints(0, 0, 2, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null, null, null, 0, false));
        exportSourcesWithCanaryButton = new JButton();
        exportSourcesWithCanaryButton.setText("Export Sources With Canary");
        panel3.add(exportSourcesWithCanaryButton,
                new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 3,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        progressBarSource = new JProgressBar();
        progressBarSource.setStringPainted(true);
        panel3.add(progressBarSource,
                new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        progressBarReflection = new JProgressBar();
        progressBarReflection.setStringPainted(true);
        panel3.add(progressBarReflection,
                new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Reflection scan");
        panel3.add(label4,
                new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Source listing");
        panel3.add(label5,
                new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_NONE,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        splitPane1.setRightComponent(panel4);
        final JSplitPane splitPane2 = new JSplitPane();
        panel4.add(splitPane2,
                new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1,
                        com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER,
                        com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK
                                | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW,
                        null, new Dimension(200, 200), null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        splitPane2.setLeftComponent(scrollPane1);
        scrollPane1.setBorder(BorderFactory.createTitledBorder(null, "Reflected Values",
                TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        resultsList = new JList();
        final DefaultListModel defaultListModel1 = new DefaultListModel();
        resultsList.setModel(defaultListModel1);
        scrollPane1.setViewportView(resultsList);
        final JSplitPane splitPane3 = new JSplitPane();
        splitPane3.setEnabled(true);
        splitPane3.setOrientation(0);
        splitPane2.setRightComponent(splitPane3);
        final JScrollPane scrollPane2 = new JScrollPane();
        scrollPane2.setAutoscrolls(false);
        scrollPane2.setHorizontalScrollBarPolicy(30);
        scrollPane2.setMinimumSize(new Dimension(30, 150));
        splitPane3.setRightComponent(scrollPane2);
        scrollPane2.setBorder(BorderFactory.createTitledBorder(null, "Sinks", TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION, null, null));
        resultSinkTable = new JTable();
        scrollPane2.setViewportView(resultSinkTable);
        final JScrollPane scrollPane3 = new JScrollPane();
        scrollPane3.setHorizontalScrollBarPolicy(30);
        scrollPane3.setMinimumSize(new Dimension(30, 150));
        splitPane3.setLeftComponent(scrollPane3);
        scrollPane3.setBorder(BorderFactory.createTitledBorder(null, "Sources", TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION, null, null));
        resultSourceTable = new JTable();
        resultSourceTable.setAutoCreateRowSorter(true);
        resultSourceTable.setAutoResizeMode(4);
        resultSourceTable.setColumnSelectionAllowed(false);
        resultSourceTable.setEnabled(true);
        resultSourceTable.setVisible(true);
        scrollPane3.setViewportView(resultSourceTable);
    }

}
