package com.scanner.security.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.scanner.security.model.ScanResult;
import com.scanner.security.repository.ScanResultRepo;
import com.scanner.security.scanner.AdultContentScanner;
import com.scanner.security.scanner.KeyWordsScanner;
import com.scanner.security.scanner.LinksScanner;
import com.scanner.security.scanner.SensitiveDataScanner;
import com.scanner.security.util.FileExtractor;

@Service
public class FileScanService {

    private final ScanResultRepo repo;
    private final RiskScoreService rss;

    public FileScanService(ScanResultRepo repo, RiskScoreService rss) {
        this.repo = repo;
        this.rss  = rss;
    }

    public ScanResult scanFile(MultipartFile file) {

        
        FileExtractor        fe  = new FileExtractor();
        FileTypeScanner      fts = new FileTypeScanner();
        KeyWordsScanner      ks  = new KeyWordsScanner();
        SensitiveDataScanner sdc = new SensitiveDataScanner();
        LinksScanner         ls  = new LinksScanner();
        ScriptScanner        ss  = new ScriptScanner();
        AdultContentScanner  acs = new AdultContentScanner();

        
        String content = fe.extractText(file);

        
        List<String> findings = new ArrayList<>();

        findings.addAll(fts.scanFileType(file.getOriginalFilename()));
        findings.addAll(ks.scanKeywords(content));
        findings.addAll(sdc.scanSensitiveWords(content));
        findings.addAll(ls.scanLinks(content));
        findings.addAll(ss.scanScripts(content));
        findings.addAll(acs.scanContent(content));  

        
        int riskScore = rss.calculateScore(findings);

        
        String status;
        if (riskScore == 0)        status = "Safe";
        else if (riskScore <= 30)  status = "Suspicious";
        else                       status = "Dangerous";

        
        String severity;
        if (riskScore == 0)        severity = "LOW";
        else if (riskScore <= 20)  severity = "MEDIUM";
        else if (riskScore <= 50)  severity = "HIGH";
        else                       severity = "CRITICAL";

        
        ScanResult result = new ScanResult();
        result.setFileName(file.getOriginalFilename());
        result.setScanType("File scan");
        result.setRiskScore(riskScore);
        result.setStatus(status);
        result.setSeverity(severity);
        result.setFindings(
            findings.isEmpty() ? "No threats detected"
                               : String.join(", ", findings));
        result.setTimestamp(LocalDateTime.now());

        return repo.save(result);
    }

    

    public List<ScanResult> getAllScans() {
        return repo.findAllByOrderByTimestampDesc();
    }

    public void deleteScan(Long id) {
        repo.deleteById(id);
    }

    public ScanResult getScanById(Long id) {
        return repo.findById(id)
            .orElseThrow(() ->
                new RuntimeException("Scan not found with id: " + id));
    }
}