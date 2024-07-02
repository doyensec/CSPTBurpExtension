package com.doyensec.ClientSidePathTraversal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JTabbedPane;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.utilities.RandomUtils;

public class ClientSidePathTraversal implements BurpExtension {

    private final String version = "1";
    private MontoyaApi api;
    public MontoyaApi getApi() {
        return api;
    }

    // Tabs
    private ClientSidePathTraversalForm csptForm;
    public ClientSidePathTraversalForm getCsptForm() {
        return csptForm;
    }
    private FalsePositivesForm falsePositivesForm;

    // CSPT Scan params
    private List<String> sinkHTTPMethods = new ArrayList<>();
    public List<String> getSinkHTTPMethods() {
        return sinkHTTPMethods;
    }
    public void setSinkHTTPMethods(List<String> sinkHTTPMethods) {
        this.sinkHTTPMethods = sinkHTTPMethods;
    }

    private String sinkScope = ".*";
    public String getSinkScope() {
        return sinkScope;
    }
    public void setSinkScope(String sinkScope) {
        this.sinkScope = sinkScope;
    }

    private String sourceScope = ".*";
    public String getSourceScope() {
        return sourceScope;
    }
    public void setSourceScope(String sourceScope) {
        this.sourceScope = sourceScope;
    }

    private Map<String, Set<String>> falsePositivesList = new HashMap<>();
    public Map<String, Set<String>> getFalsePositivesList() {
        return falsePositivesList;
    }

    private String canary;
    public String getCanary() {
        return canary;
    }
    public void setCanary(String canary) {
        this.canary = canary;
    }

    private Map<String, Set<PotentialSink>> pathLookup = new HashMap<>();
    public Map<String, Set<PotentialSink>> getPathLookup() {
        return pathLookup;
    }

    private Map<String, Set<PotentialSource>> paramValueLookup = new HashMap<>();
    public Map<String, Set<PotentialSource>> getParamValueLookup() {
        return paramValueLookup;
    }


    // Utility methods

    public String generateCanaryToken() {
        return api.utilities().randomUtils().randomString(12, RandomUtils.CharacterSet.ASCII_LETTERS);
    }

    public void addFalsePositive(String getParameterName, String urlRegexp) {
        falsePositivesList.computeIfAbsent(getParameterName, x -> new HashSet<>()).add(urlRegexp);
        falsePositivesForm.display(this);
    }

    public void removeFalsePositive(String getParameterName, String urlRegexp) {
        Set<String> urlSet = falsePositivesList.get(getParameterName);
        if (urlSet == null) return;

        urlSet.remove(urlRegexp);

        if (urlSet.isEmpty()) {
            falsePositivesList.remove(getParameterName);
        }

        falsePositivesForm.display(this);
    }

    private boolean checkIfFalsePositive(PotentialSource ptSource) {
        Set<String> falsePositiveURLs = falsePositivesList.get(ptSource.paramName);
        if (falsePositiveURLs == null) {
            return false;
        }

        for (String falsePositiveURL : falsePositiveURLs) {
            if (ptSource.sourceURL.matches(falsePositiveURL)) {
                api.logging().logToOutput("False positive identification: " + ptSource); // TODO: is ptSource right here?
                return true;
            }
        }

        return false;
    }

    public boolean addNewSource(String getParameterName, String getParameterValue, String url) {
        PotentialSource ptSource = new PotentialSource(getParameterName, getParameterValue.toLowerCase(), url);

        // This source is present in falsePositive list
        if (checkIfFalsePositive(ptSource)) {
            return false;
        }

        this.paramValueLookup.computeIfAbsent(getParameterValue.toLowerCase(), x -> new HashSet<>()).add(ptSource);
        return true;
    }

    // Plugin init
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("Client-Side Path Traversal v" + version);
        this.api.scanner().registerScanCheck(new ClientSidePathTraversalPassiveScan(api, this));
        this.api.logging().logToOutput("Extension has been loaded.");

        loadData();

        csptForm = new ClientSidePathTraversalForm(this);
        falsePositivesForm = new FalsePositivesForm(this);
        JTabbedPane tabPane = new JTabbedPane();
        tabPane.addTab("CSPT", csptForm.$$$getRootComponent$$$());
        tabPane.addTab("False Positives List", falsePositivesForm.$$$getRootComponent$$$());
        this.api.userInterface().registerSuiteTab("CSPT", tabPane);
    }

    // Project file persistence
    public void saveData() {
        PersistedObject data = api.persistence().extensionData();
        PersistedList<String> persisList = PersistedList.persistedStringList();
        persisList.addAll(sinkHTTPMethods);
        data.setStringList("sinkHTTPMethods", persisList);
        data.setString("sinkScope", sinkScope);
        data.setString("sourceScope", sourceScope);
        data.setString("canary", canary);

        PersistedList<String> falsePositiveParam = PersistedList.persistedStringList();
        PersistedList<String> falsePositiveURL = PersistedList.persistedStringList();

        for (String param : falsePositivesList.keySet()) {
            for (String url : falsePositivesList.get(param)) {
                falsePositiveParam.add(param);
                falsePositiveURL.add(url);
            }
        }
        data.setStringList("falsePositiveParam", falsePositiveParam);
        data.setStringList("falsePositiveURL", falsePositiveURL);
    }

    public void loadData() {
        PersistedObject data = api.persistence().extensionData();
        if (data.getString("sinkScope") != null) {
            sinkScope = data.getString("sinkScope");
        }

        if (data.getString("sourceScope") != null) {
            sourceScope = data.getString("sourceScope");
        }

        if (data.getString("canary") != null) {
            canary = data.getString("canary");
        } else {
            canary = generateCanaryToken();
        }
        if (data.getStringList("sinkHTTPMethods") != null) {
            sinkHTTPMethods = data.getStringList("sinkHTTPMethods");
        }
        List<String> falsePositiveParam = data.getStringList("falsePositiveParam");
        List<String> falsePositiveURL = data.getStringList("falsePositiveURL");

        if (falsePositiveParam != null && falsePositiveURL != null
                && falsePositiveParam.size() == falsePositiveURL.size()) {
            for (int i = 0; i < falsePositiveParam.size(); i++) {
                addFalsePositive(falsePositiveParam.get(i), falsePositiveURL.get(i));
            }
        }

    }

    // Scan methods
    public void step1ListSource(CSPTScannerTask csptScannerTask) {
        saveData();
        printDebugInformationAboutRun();
        this.paramValueLookup.clear();
        this.pathLookup.clear();

        // After processing, the filter will contain all the data
        ProxyFilterPotentialSource sourceFilter = new ProxyFilterPotentialSource(this, csptScannerTask);
        api.logging().logToOutput("Scan started");

        api.proxy().history(sourceFilter);
        // TODO: nothing happens after the filter is invoked?
    }

    public void step2findReflection(CSPTScannerTask csptScannerTask) {
        if (!paramValueLookup.isEmpty()) {
            ProxyFilterPotentialSink filter = new ProxyFilterPotentialSink(this, csptScannerTask);
            api.logging().logToOutput("Scan for Sink started");

            // After processing, the filter will contain all the data
            api.proxy().history(filter);
            this.pathLookup = filter.getPathLookup();
            printDebugResultsAboutRun();
        }
    }

    public List<burp.api.montoya.proxy.ProxyHttpRequestResponse> getExploitableSink(String httpMethod, String host) {
        ProxyFilterExploitableSink filter = new ProxyFilterExploitableSink(httpMethod, host);
        api.logging().logToOutput("Scanning for exploitable sink:" + httpMethod + ":" + host);

        List<ProxyHttpRequestResponse> exploitableSinks = api.proxy().history(filter);

        for (ProxyHttpRequestResponse proxyHttpRequestResponse : exploitableSinks) {
            api.logging().logToOutput(proxyHttpRequestResponse.finalRequest().url());
            api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(
                    proxyHttpRequestResponse.finalRequest(), proxyHttpRequestResponse.originalResponse()));
        }
        return exploitableSinks;
    }

    public String replaceParamWithCanary(String param, String url) {
        HttpRequest http = HttpRequest.httpRequestFromUrl(url);
        HttpRequest finalHttp = http.withUpdatedParameters(HttpParameter.urlParameter(param, canary));
        api.logging().logToOutput(param + ":" + canary + ":" + url + ":" + finalHttp.url());
        return finalHttp.url();
    }

    public List<String> getAllSourcesWithCanary() {
        List<String> urlsWithCanary = new ArrayList<>();
        for (String paramValue : pathLookup.keySet()) {
            for (PotentialSource source : paramValueLookup.get(paramValue)) {
                urlsWithCanary.add(replaceParamWithCanary(source.paramName, source.sourceURL));
            }
        }
        return urlsWithCanary;
    }

    // Debug methods
    private void printDebugInformationAboutRun() {
        api.logging().logToOutput("sourceScope: " + sinkScope);
        api.logging().logToOutput("sinkScope: " + sinkScope);
        api.logging().logToOutput("sinkHTTPMethods:");
        for (String httpMethod : sinkHTTPMethods) {
            api.logging().logToOutput("-" + httpMethod);
        }
    }

    private void printDebugResultsAboutRun() {
        // We have finding
        if (!getPathLookup().isEmpty()) {
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
