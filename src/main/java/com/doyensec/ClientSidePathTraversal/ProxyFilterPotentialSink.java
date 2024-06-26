package com.doyensec.ClientSidePathTraversal;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class ProxyFilterPotentialSink implements ProxyHistoryFilter {
    private final Pattern scope;
    Map<String, Set<PotentialSource>> paramValueLookup;
    int currentScan = 0;
    int lastScanUpdate = 0;
    private List<String> sinkHTTPMethods;

    ClientSidePathTraversal cspt;

    CSPTScannerTask csptScannerTask;
    private Map<String, Set<PotentialSink>> pathLookup;
    MontoyaApi api;

    public ProxyFilterPotentialSink(MontoyaApi api, ClientSidePathTraversal cspt, CSPTScannerTask csptScannerTask,
            String scope, List<String> sinkHTTPMethods, Map<String, Set<PotentialSource>> paramValueLookup) {
        this.api = api;
        this.paramValueLookup = paramValueLookup;
        this.pathLookup = new HashMap<String, Set<PotentialSink>>();
        this.sinkHTTPMethods = sinkHTTPMethods;
        this.scope = Pattern.compile(scope, Pattern.CASE_INSENSITIVE);
        this.cspt = cspt;
        this.csptScannerTask = csptScannerTask;
        this.currentScan = 0;
        this.lastScanUpdate = 0;
    }

    public Map<String, Set<PotentialSink>> getPathLookup() {
        return pathLookup;
    }

    /* 
     This method implements the logic to find sink.
     It looks for reflection*/
    @Override
    public boolean matches(ProxyHttpRequestResponse requestResponse) {
        currentScan = currentScan + 1;

        if (lastScanUpdate + 100 < currentScan) {
            lastScanUpdate = currentScan;

            csptScannerTask.updateProgressReflection(this.currentScan);
        }

        HttpRequest httpRequest = requestResponse.finalRequest();

        // If the HTTP Method is not a valid one
        if (httpRequest.method().equals("OPTIONS") || !sinkHTTPMethods.contains(httpRequest.method())) {
            return false;
        }

        if (!this.scope.matcher(httpRequest.url()).find()) {
            return false;
        }

        // Check reflection in path
        String[] pathParams = httpRequest.pathWithoutQuery().split("/");

        // For each URI param check if value correspond to path param
        for (String pathParam : pathParams) {

            // We check reflection in lower case, we don't check for a transformed value
            if (!pathParam.isEmpty() && paramValueLookup.containsKey(pathParam.toLowerCase())) {

                api.logging().logToOutput(
                        httpRequest.method() + ";" + pathParam.toLowerCase() + " found in " + httpRequest.url());

                pathLookup
                        .computeIfAbsent(pathParam.toLowerCase(),
                                (x -> (Set<PotentialSink>) new HashSet<PotentialSink>()))
                        .add(new PotentialSink(httpRequest.method(), httpRequest.url()));

                return true;
            }

        }

        return false;

    }

}
