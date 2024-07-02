package com.doyensec.ClientSidePathTraversal;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

import java.util.List;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public class ClientSidePathTraversalPassiveScan implements ScanCheck {

    MontoyaApi api;
    ClientSidePathTraversal cspt;

    public ClientSidePathTraversalPassiveScan(MontoyaApi api, ClientSidePathTraversal cspt) {
        this.api = api;
        this.cspt = cspt;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return null;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> auditIssueList = emptyList();

        String path = baseRequestResponse.request().pathWithoutQuery().toLowerCase();

        if (path.contains(cspt.getCanary().toLowerCase())) {
            auditIssueList = singletonList(
                    auditIssue(
                            "Potential Client-Side Path Traversal",
                            "The PATH " + path + " contains the canary: "+ cspt.getCanary(),
                            null,
                            baseRequestResponse.request().url(),
                            AuditIssueSeverity.MEDIUM,
                            AuditIssueConfidence.FIRM,
                            null,
                            null,
                            AuditIssueSeverity.MEDIUM,
                            baseRequestResponse
                    )
            );
        }
        return auditResult(auditIssueList);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }
}
