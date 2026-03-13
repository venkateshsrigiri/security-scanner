package com.scanner.security.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.scanner.security.model.ScanResult;
import com.scanner.security.repository.ScanResultRepo;
import com.scanner.security.scanner.AdultContentScanner;
import com.scanner.security.scanner.UrlSafetyScanner;

@Service
public class UrlScanService {

    private final ScanResultRepo repo;
    private final VirusTotalService vs;
    private final WebContentFetcher wcf;
    private final RiskScoreService rss;

    public UrlScanService(ScanResultRepo repo,
                          VirusTotalService vs,
                          WebContentFetcher wcf,
                          RiskScoreService rss) {
        this.repo = repo;
        this.vs   = vs;
        this.wcf  = wcf;
        this.rss  = rss;
    }

    public ScanResult scanUrl(String url) {

    List<String> findings = new ArrayList<>();

    
    UrlSafetyScanner scanner = new UrlSafetyScanner();
    findings.addAll(scanner.scanUrl(url));

    
    AdultContentScanner acs = new AdultContentScanner();
    findings.addAll(acs.scanUrl(url));

    
    String vtResult = vs.checkUrl(url);
    if (!vtResult.equals("No external threat detected")) {
        findings.add(vtResult);
    }

    
    try {
        String pageContent = wcf.fetchContent(url);
        if (pageContent != null && !pageContent.isBlank()) {
            String lower = pageContent.toLowerCase();
            if (lower.contains("enter your password")
                    || lower.contains("confirm your password")
                    || lower.contains("verify your identity")
                    || lower.contains("your account has been suspended")) {
                findings.add(
                    "Suspicious webpage content detected — "
                    + "page contains phishing language");
            }
        }
    } catch (Exception e) {
        
    }

    
    int riskScore = rss.calculateScore(findings);

    
    String status;
    if (riskScore == 0)       status = "Safe";
    else if (riskScore <= 30) status = "Suspicious";
    else                      status = "Dangerous";

    
    String severity;
    if (riskScore == 0)        severity = "LOW";
    else if (riskScore <= 20)  severity = "MEDIUM";
    else if (riskScore <= 50)  severity = "HIGH";
    else                       severity = "CRITICAL";

    
    ScanResult result = new ScanResult();
    result.setFileName(url);
    result.setScanType("URL scan");
    result.setRiskScore(riskScore);
    result.setStatus(status);
    result.setSeverity(severity);
    result.setFindings(
        findings.isEmpty() ? "No threats detected"
                           : String.join(", ", findings));
    result.setTimestamp(LocalDateTime.now());

    return repo.save(result);
}
}
