package com.doyensec.ClientSidePathTraversal;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class ProxyFilterPotentialSource implements ProxyHistoryFilter {

    MontoyaApi api;
    Pattern scope;

    int currentScan = 0;
    int lastScanUpdate = 0;
    ClientSidePathTraversal cspt;
    CSPTScannerTask csptScannerTask;

    private Map<String, Set<PotentialSource>> paramValueLookup;

    public ProxyFilterPotentialSource(MontoyaApi api, ClientSidePathTraversal cspt, CSPTScannerTask csptScannerTask) {
        this.api = api;
        this.cspt = cspt;

        this.scope = Pattern.compile(cspt.getSourceScope(), Pattern.CASE_INSENSITIVE);

        paramValueLookup = new HashMap<>();
        this.csptScannerTask = csptScannerTask;
        this.currentScan = 0;
        this.lastScanUpdate = 0;

    }

    public Map<String, Set<PotentialSource>> getParamValueLookup() {
        return paramValueLookup;
    }

    @Override
    public boolean matches(ProxyHttpRequestResponse requestResponse) {

        this.currentScan = this.currentScan + 1;

        if (lastScanUpdate + 100 < currentScan) {
            lastScanUpdate = currentScan;

            csptScannerTask.updateProgressSource(this.currentScan);
        }

        // Only check text/html responses
        HttpResponse httpResponse = requestResponse.originalResponse();
        if (httpResponse == null || httpResponse.statedMimeType() != burp.api.montoya.http.message.MimeType.HTML) {
            return false;
        }

        // Avoid 4XX and 5XX page but we want to keep 3XX
        if (httpResponse.statusCode() > 400) {
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

        // Must match the soruce scope
        if (!this.scope.matcher(httpRequest.url().toString()).find()) {
            return false;
        }

        boolean fitlered = false;
        for (ParsedHttpParameter params : httpRequest.parameters()) {

            // At least one Query Parameter
            if (params.type() == HttpParameterType.URL) {

                // Add new source to list if it is not a false positive
                if (cspt.addNewSource(params.name(), params.value().toLowerCase(), httpRequest.url())) {
                    fitlered = true;
                }

            }
        }

        return fitlered;
    }

}
