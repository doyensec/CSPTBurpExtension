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

    private ClientSitePathTraversalForm csptForm;

    ClientSitePathTraversalForm listener = null;
    private FalsePositivesForm falsePositivesForm;
    private MontoyaApi api;

    private List<String> sinkHTTPMethods;

    private String sinkScope;
    private String sourceScope;
    private String canary;

    private Map<String, Set<PotentialSource>> paramValueLookup;


    private Map<String, Set<String>> falsePositivesList;


    private Map<String, Set<PotentialSink>> pathLookup;

    public ClientSitePathTraversalForm getCsptForm() {
        return csptForm;
    }

    public MontoyaApi getApi() {
        return api;
    }

    public String generateCanaryToken() {
        return api.utilities().randomUtils().randomString(12, RandomUtils.CharacterSet.ASCII_LETTERS);
    }

    public String getCanary() {
        return canary;
    }

    public Map<String, Set<String>> getFalsePositivesList() {
        return falsePositivesList;
    }

    public List<String> getSinkHTTPMethods() {
        return sinkHTTPMethods;
    }

    public void setSinkHTTPMethods(List<String> sinkHTTPMethods) {
        this.sinkHTTPMethods = sinkHTTPMethods;
    }

    public String getSinkScope() {
        return sinkScope;
    }

    public void setSinkScope(String sinkScope) {
        this.sinkScope = sinkScope;
    }

    public String getSourceScope() {
        return sourceScope;
    }

    public void setSourceScope(String sourceScope) {
        this.sourceScope = sourceScope;
    }

    public Map<String, Set<PotentialSource>> getParamValueLookup() {
        return paramValueLookup;
    }

    public void step1ListSource(CSPTScannerTask csptScannerTask) {
        saveData();
        printDebugInformationAboutRun();
        paramValueLookup = new HashMap<>();
        pathLookup = new HashMap<>();
        
        // After processing, the filter will contain all the data 
        ProxyFilterPotentialSource sourceFilter = new ProxyFilterPotentialSource(api, this, csptScannerTask);
        api.logging().logToOutput("Scan started");

        api.proxy().history(sourceFilter);
    }

    public void step2findReflection(CSPTScannerTask csptScannerTask) {
        if (!paramValueLookup.isEmpty()) {

            ProxyFilterPotentialSink filter = new ProxyFilterPotentialSink(api, this, csptScannerTask, sinkScope,
                    sinkHTTPMethods, paramValueLookup);

            api.logging().logToOutput("Scan for Sink started");

            // After processing, the filter will contain all the data 
            api.proxy().history(filter);
            this.pathLookup = filter.getPathLookup();

            printDebugResultsAboutRun();
        }
    }

    public void addFalsePositive(String getParameterName, String urlRegexp) {
        falsePositivesList.computeIfAbsent(getParameterName, (x -> {
            Set<String> lstURL = new HashSet<>();
            return lstURL;
        })).add(urlRegexp);

        if (falsePositivesForm != null) {
            falsePositivesForm.display(this);
        }
    }

    public void removeFalsePositive(String getParameterName, String urlRegexp) {
        if (falsePositivesList.get(getParameterName) != null
                && falsePositivesList.get(getParameterName).contains(urlRegexp)) {
            falsePositivesList.get(getParameterName).remove(urlRegexp);
        }
        if (falsePositivesList.get(getParameterName).isEmpty()) {
            falsePositivesList.remove(getParameterName);
        }

        falsePositivesForm.display(this);
    }

    public boolean addNewSource(String getParameterName, String getParameterValue, String url) {

        PotentialSource ptSource = new PotentialSource(getParameterName, getParameterValue.toLowerCase(), url);

        // This source is present in falsePositive list
        if (checkIfFalsePositive(ptSource)) {
            return false;
        }

        paramValueLookup.computeIfAbsent(getParameterValue.toLowerCase(), (x -> {
            Set<PotentialSource> lstSource = new HashSet<>();
            return lstSource;
        })).add(ptSource);
        return true;
    }

    public Map<String, Set<PotentialSink>> getPathLookup() {
        return pathLookup;
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("Client-Side Path Traversal v" + version);

        api.scanner().registerScanCheck(new ClientSidePathTraversalPassiveScan(api, this));

        this.api.logging().logToOutput("Extension has been loaded.");

        sourceScope = ".*";
        sinkScope = ".*";
        sinkHTTPMethods = new ArrayList<>();
        falsePositivesList = new HashMap<>();

        loadData();

        csptForm = new ClientSitePathTraversalForm(this);

        falsePositivesForm = new FalsePositivesForm(this);
        JTabbedPane tabPane = new JTabbedPane();
        tabPane.addTab("CSPT", csptForm.$$$getRootComponent$$$());
        tabPane.addTab("False Positives List", falsePositivesForm.$$$getRootComponent$$$());

        this.api.userInterface().registerSuiteTab("CSPT", tabPane);

    }

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

    public List<burp.api.montoya.proxy.ProxyHttpRequestResponse> getExploitableSink(String httpMethod, String host) {
        ProxyFilterExploitableSink filter = new ProxyFilterExploitableSink(api, httpMethod, host);
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

    public void setCanary(String canary) {
        this.canary = canary;
    }

    private boolean checkIfFalsePositive(PotentialSource ptSource) {

        Set<String> falsePositiveURLs = falsePositivesList.get(ptSource.paramName);
        if (falsePositiveURLs == null) {
            return false;
        }

        for (String falsePositiveURL : falsePositiveURLs) {

            if (ptSource.sourceURL.matches(falsePositiveURL)) {

                api.logging().logToOutput("False positive identification:" + ptSource);
                return true;
            }
        }

        return false;
    }

    private void printDebugInformationAboutRun() {
        api.logging().logToOutput("sourceScope:" + sinkScope);
        api.logging().logToOutput("sinkScope:" + sinkScope);
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
