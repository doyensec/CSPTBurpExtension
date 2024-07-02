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
    final Map<String, Set<PotentialSource>> paramValueLookup;
    int currentScan;
    int lastScanUpdate;
    private List<String> sinkHTTPMethods;

    ClientSidePathTraversal cspt;

    CSPTScannerTask csptScannerTask;
    private Map<String, Set<PotentialSink>> pathLookup;
    MontoyaApi api;

    public ProxyFilterPotentialSink(ClientSidePathTraversal cspt, CSPTScannerTask csptScannerTask) {
        this.api = cspt.getApi();
        this.paramValueLookup = cspt.getParamValueLookup();
        this.pathLookup = new HashMap<>();
        this.sinkHTTPMethods = cspt.getSinkHTTPMethods();
        this.scope = Pattern.compile(cspt.getSinkScope(), Pattern.CASE_INSENSITIVE);
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
        currentScan++;

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
        // For each URI param check if value correspond to path param
        for (String pathParam : httpRequest.pathWithoutQuery().split("/")) {
            // We check reflection in lower case, we don't check for a transformed value
            if (!pathParam.isEmpty() && paramValueLookup.containsKey(pathParam.toLowerCase())) {
                api.logging().logToOutput(httpRequest.method() + ";" + pathParam.toLowerCase() + " found in " + httpRequest.url());

                pathLookup
                        .computeIfAbsent(pathParam.toLowerCase(), x -> new HashSet<>())
                        .add(new PotentialSink(httpRequest.method(), httpRequest.url()));
                return true;
            }
        }
        return false;
    }
}
