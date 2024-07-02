package com.doyensec.ClientSidePathTraversal;

import burp.api.montoya.MontoyaApi;

import javax.swing.SwingWorker;
import java.util.*;

public class CSPTScannerTask extends SwingWorker<String, Object> {
    private ClientSidePathTraversal cspt;
    private ClientSidePathTraversalForm csptForm;
    private MontoyaApi api;

    private Map<String, Set<PotentialSink>> pathLookup = new HashMap<>();
    public Map<String, Set<PotentialSink>> getPathLookup() {
        return pathLookup;
    }

    private Map<String, Set<PotentialSource>> paramValueLookup = new HashMap<>();
    public Map<String, Set<PotentialSource>> getParamValueLookup() {
        return paramValueLookup;
    }

    int scanProxyTotal = 0;
    int scanProxyCurrent = 0;
    boolean executed = false;

    CSPTScannerTask(ClientSidePathTraversal cspt) {
        this.cspt = cspt;
        this.csptForm = cspt.getCsptForm();
        this.api = cspt.getApi();
    }

    // UI Progress methods

    private void initProgressSource() {
        this.scanProxyCurrent = 0;
        csptForm.initProgressSource();
        updateProgressSource(0);
        updateProgressReflection(0);
    }

    private void initProgressReflection() {
        this.scanProxyCurrent = 0;
        csptForm.initProgressReflection();
    }

    public void updateProgressSource(int scanProxyCurrent) {
        csptForm.setProgressSource(100 * scanProxyCurrent / this.scanProxyTotal);
    }

    public void updateProgressReflection(int scanProxyCurrent) {
        csptForm.setProgressReflection(100 * scanProxyCurrent / this.scanProxyTotal);
    }

    private void finishProgressSource() {
        csptForm.finishProgressSource();
    }

    private void finishProgressReflection() {
        csptForm.finishProgressReflection();
    }


    // Main async method
    @Override
    protected String doInBackground() {
        // Ensure that a Scanner Task is never executed twice
        assert(!this.executed);
        executed = true;

        this.cspt.saveData();
        this.cspt.printDebugInformationAboutRun();

        // This will fill paramValueLookup with potentialSource
        this.scanProxyTotal = cspt.getApi().proxy().history().size();

        // STEP 1: Get sources
        this.cspt.getApi().logging().logToOutput("Scan started");
        this.initProgressSource();
        this.step1ListSource();
        this.finishProgressSource();

        // STEP 2: identify reflections
        this.initProgressReflection();
        this.step2findReflection();
        this.finishProgressReflection();

        this.printDebugResultsAboutRun();

        this.csptForm.displayResults(this);

        return "";
    }

    // Scan methods
    public void step1ListSource() {
        ProxyFilterPotentialSource sourceFilter = new ProxyFilterPotentialSource(this.cspt, this);
        api.logging().logToOutput("Scan started");

        // Filter fills an internal list with valid values, so we don't have to iterate over the requests again
        api.proxy().history(sourceFilter);

        this.paramValueLookup.putAll(sourceFilter.getParamValueLookup());
    }

    public void step2findReflection() {
        if (!paramValueLookup.isEmpty()) {
            ProxyFilterPotentialSink filter = new ProxyFilterPotentialSink(this.cspt, this);
            api.logging().logToOutput("Scan for Sink started");

            // After processing, the filter will contain all the data
            api.proxy().history(filter);
            this.pathLookup.putAll(filter.getPathLookup());
        }
    }

    public List<String> getAllSourcesWithCanary() {
        List<String> urlsWithCanary = new ArrayList<>();
        for (String paramValue : pathLookup.keySet()) {
            for (PotentialSource source : paramValueLookup.get(paramValue)) {
                urlsWithCanary.add(this.cspt.replaceParamWithCanary(source.paramName, source.sourceURL));
            }
        }
        return urlsWithCanary;
    }

    public void printDebugResultsAboutRun() {
        if (!getPathLookup().isEmpty()) {
            // We have findings
            api.logging().logToOutput("We found " + pathLookup.size() + " findings");
            for (String key : getPathLookup().keySet()) {

                // The following source hit the following sink
                Set<PotentialSource> sources = paramValueLookup.get(key);
                Set<PotentialSink> sinks = getPathLookup().get(key);
                api.logging().logToOutput("The following sources:");
                for (PotentialSource source : sources) {
                    api.logging().logToOutput(source.paramValue + ":" + source.paramName + ":" + source.sourceURL);
                }
                api.logging().logToOutput("Hit the following sink:");
                for (PotentialSink sink : sinks) {
                    api.logging().logToOutput(sink.method + ":" + sink.url);
                }
            }
        }
    }
}
