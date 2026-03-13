package com.scanner.security.dto;

import java.time.LocalDateTime;

import com.scanner.security.model.ScanResult;

public class ScanReportDTO {

    // Matches exactly what ReportPanel.jsx reads:
    // report.id
    private Long id;

    // report.fileName
    private String fileName;

    // report.scanType  ("File scan" or "URL scan")
    private String scanType;

    // report.riskScore
    private int riskScore;

    // report.status  ("Safe", "Suspicious", "Dangerous")
    private String status;

    // report.severity  ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    private String severity;

    // report.findings  (comma separated string)
    private String findings;

    // report.timestamp
    private LocalDateTime timestamp;

    // ── Constructors ───────────────────────────────────────────

    public ScanReportDTO() {}

    // Build a DTO from your ScanResult entity
    public static ScanReportDTO fromEntity(ScanResult result) {
        ScanReportDTO dto = new ScanReportDTO();
        dto.setId(result.getId());
        dto.setFileName(result.getFileName());
        dto.setScanType(result.getScanType());
        dto.setRiskScore(result.getRiskScore());
        dto.setStatus(result.getStatus());
        dto.setSeverity(result.getSeverity());
        dto.setFindings(result.getFindings());
        dto.setTimestamp(result.getTimestamp());
        return dto;
    }

    // ── Getters and Setters ────────────────────────────────────

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }

    public String getScanType() { return scanType; }
    public void setScanType(String scanType) { this.scanType = scanType; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getFindings() { return findings; }
    public void setFindings(String findings) { this.findings = findings; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}