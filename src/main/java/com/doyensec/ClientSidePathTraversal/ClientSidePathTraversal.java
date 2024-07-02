package com.doyensec.ClientSidePathTraversal;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.utilities.RandomUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.JTabbedPane;

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

  // Utility methods
  public String generateCanaryToken() {
    return api.utilities().randomUtils().randomString(12, RandomUtils.CharacterSet.ASCII_LETTERS);
  }

  public void addFalsePositive(String getParameterName, String urlRegexp) {
    this.falsePositivesList.computeIfAbsent(getParameterName, x -> new HashSet<>()).add(urlRegexp);
    this.falsePositivesForm.refresh();
    this.saveData();
  }

  public void removeFalsePositive(String getParameterName, String urlRegexp) {
    Set<String> urlSet = falsePositivesList.get(getParameterName);
    if (urlSet == null) return;

    urlSet.remove(urlRegexp);

    if (urlSet.isEmpty()) {
      falsePositivesList.remove(getParameterName);
    }

    falsePositivesForm.refresh();
  }

  public boolean checkIfFalsePositive(PotentialSource ptSource) {
    Set<String> falsePositiveURLs = falsePositivesList.get(ptSource.paramName);
    if (falsePositiveURLs == null) {
      return false;
    }

    for (String falsePositiveURL : falsePositiveURLs) {
      if (ptSource.sourceURL.matches(falsePositiveURL)) {
        api.logging()
            .logToOutput(
                "False positive identification: "
                    + falsePositiveURL); // TODO: is ptSource right here?
        return true;
      }
    }

    return false;
  }

  public String replaceParamWithCanary(String param, String url) {
    HttpRequest http = HttpRequest.httpRequestFromUrl(url);
    HttpRequest finalHttp = http.withUpdatedParameters(HttpParameter.urlParameter(param, canary));
    api.logging().logToOutput(param + ":" + canary + ":" + url + ":" + finalHttp.url());
    return finalHttp.url();
  }

  public List<burp.api.montoya.proxy.ProxyHttpRequestResponse> getExploitableSinks(
      String httpMethod, String host) {
    ProxyFilterExploitableSink filter = new ProxyFilterExploitableSink(httpMethod, host);
    api.logging().logToOutput("Scanning for exploitable sink:" + httpMethod + ":" + host);

    List<ProxyHttpRequestResponse> exploitableSinks = api.proxy().history(filter);

    for (ProxyHttpRequestResponse proxyHttpRequestResponse : exploitableSinks) {
      api.logging().logToOutput(proxyHttpRequestResponse.finalRequest().url());
      api.organizer()
          .sendToOrganizer(
              HttpRequestResponse.httpRequestResponse(
                  proxyHttpRequestResponse.finalRequest(),
                  proxyHttpRequestResponse.originalResponse()));
    }
    return exploitableSinks;
  }

  // Params persistence in project file
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

    if (falsePositiveParam != null
        && falsePositiveURL != null
        && falsePositiveParam.size() == falsePositiveURL.size()) {
      for (int i = 0; i < falsePositiveParam.size(); i++) {
        // Do not use "addFalsePositive" here as the false positive form is not initialized yet at
        // this point in time
        falsePositivesList
            .computeIfAbsent(falsePositiveParam.get(i), x -> new HashSet<>())
            .add(falsePositiveURL.get(i));
      }
    }
  }

  // Debug methods
  public void printDebugInformationAboutRun() {
    api.logging().logToOutput("sourceScope: " + sinkScope);
    api.logging().logToOutput("sinkScope: " + sinkScope);
    api.logging().logToOutput("sinkHTTPMethods:");
    for (String httpMethod : sinkHTTPMethods) {
      api.logging().logToOutput("-" + httpMethod);
    }
  }
}
