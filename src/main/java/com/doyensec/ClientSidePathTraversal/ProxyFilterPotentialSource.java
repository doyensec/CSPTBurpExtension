package com.doyensec.ClientSidePathTraversal;

import java.util.*;
import java.util.regex.Pattern;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class ProxyFilterPotentialSource implements ProxyHistoryFilter {

    private Pattern scope;
    private int currentScan;
    private ClientSidePathTraversal cspt;
    private CSPTScannerTask csptScannerTask;
    private Map<String, Set<PotentialSource>> paramValueLookup = new HashMap<>();
    public Map<String, Set<PotentialSource>> getParamValueLookup() {
        return paramValueLookup;
    }

    public ProxyFilterPotentialSource(ClientSidePathTraversal cspt, CSPTScannerTask csptScannerTask) {
        this.cspt = cspt;
        this.scope = Pattern.compile(cspt.getSourceScope(), Pattern.CASE_INSENSITIVE);

        this.csptScannerTask = csptScannerTask;
        this.currentScan = 0;
    }

    @Override
    public boolean matches(ProxyHttpRequestResponse requestResponse) {
        // Update the percent every 100 requests
        if (currentScan++ % 100 == 0) {
            csptScannerTask.updateProgressSource(this.currentScan);
        }

        // Only check text/html responses
        HttpResponse httpResponse = requestResponse.originalResponse();
        if (httpResponse == null || httpResponse.statedMimeType() != burp.api.montoya.http.message.MimeType.HTML) {
            return false;
        }

        // Avoid 4XX and 5XX page but we want to keep 3XX
        if (httpResponse.statusCode() >= 400) {
            return false;
        }

        HttpRequest httpRequest = requestResponse.finalRequest();

        // Checking if the request is a GET
        if (!httpRequest.method().equalsIgnoreCase("GET")) {
            return false;
        }

        // Some parameters must be present
        if (httpRequest.parameters().isEmpty()) {
            return false;
        }

        // Must match the source scope
        if (!this.scope.matcher(httpRequest.url()).find()) {
            return false;
        }

        boolean valid = false;
        for (ParsedHttpParameter params : httpRequest.parameters(HttpParameterType.URL)) {
            PotentialSource ptSource = new PotentialSource(params.name(), params.value().toLowerCase(), httpRequest.url());

            if (!this.cspt.checkIfFalsePositive(ptSource)) {
                valid = true;
                this.paramValueLookup.computeIfAbsent(ptSource.paramValue, x -> new HashSet<>()).add(ptSource);
            }
        }

        return valid;
    }
}
