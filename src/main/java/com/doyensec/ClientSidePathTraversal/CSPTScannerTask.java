package com.doyensec.ClientSidePathTraversal;

import javax.swing.SwingWorker;

public class CSPTScannerTask extends SwingWorker<String, Object> {
    private ClientSidePathTraversal cspt = null;
    private ClientSitePathTraversalForm csptForm = null;

    int scanProxyTotal = 0;
    int scanProxyCurrent = 0;

    CSPTScannerTask(ClientSidePathTraversal cspt) {
        this.cspt = cspt;
        this.csptForm = cspt.getCsptForm();
    }

    public void initProgressSource() {
        this.scanProxyCurrent = 0;
        if (csptForm != null) {
            csptForm.initProgressSource();
            updateProgressSource(0);
            updateProgressReflection(0);
        }
    }

    public void finishProgressSource() {
        if (csptForm != null) {
            csptForm.finishProgressSource();
        }
    }

    public void updateProgressSource(int scanProxyCurrent) {
        if (csptForm != null) {

            csptForm.setProgressSource(100 * scanProxyCurrent / this.scanProxyTotal);
        }
    }

    public void initProgressReflection() {
        this.scanProxyCurrent = 0;
        if (csptForm != null) {
            csptForm.initProgressReflection();
        }
    }

    public void finishProgressReflection() {
        if (csptForm != null) {
            csptForm.finishProgressReflection();
        }
    }

    public void updateProgressReflection(int scanProxyCurrent) {
        if (csptForm != null) {

            csptForm.setProgressReflection(100 * scanProxyCurrent / this.scanProxyTotal);
        }
    }

    @Override
    protected String doInBackground() {

        // This will fill paramValueLookup with potentialSource
        scanProxyTotal = cspt.getApi().proxy().history().size();

        initProgressSource();
        cspt.getApi().logging().logToOutput("Scan started");

        cspt.step1ListSource(this);
        finishProgressSource();
        initProgressReflection();

        cspt.step2findReflection(this);
        finishProgressReflection();

        // Why we need to give cspt
        csptForm.displayResults(cspt.getParamValueLookup(), cspt.getPathLookup(), cspt);

        return "";
    }
}
