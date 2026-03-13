package com.scanner.security.controller;


import java.util.List;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.scanner.security.dto.ScanReportDTO;
import com.scanner.security.dto.UrlRequestDTO;
import com.scanner.security.model.ScanResult;
import com.scanner.security.service.FileScanService;
import com.scanner.security.service.UrlScanService;

@RestController
@RequestMapping("/scan")
@CrossOrigin(origins = "http://localhost:5173")
public class ScanController {

    private final FileScanService fs;
    private final UrlScanService us;

    public ScanController(FileScanService fs, UrlScanService us) {
        this.fs = fs;
        this.us = us;
    }

    // Returns DTO instead of raw entity
    @PostMapping("/file")
    public ScanReportDTO scanFile(
            @RequestParam("file") MultipartFile file) {
        ScanResult result = fs.scanFile(file);
        return ScanReportDTO.fromEntity(result);
    }

    // Uses UrlRequestDTO instead of UrlRequest
    @PostMapping("/url")
    public ScanReportDTO scanUrl(
            @RequestBody UrlRequestDTO request) {
        ScanResult result = us.scanUrl(request.getUrl());
        return ScanReportDTO.fromEntity(result);
    }

    // Returns list of DTOs
    @GetMapping("/history")
    public List<ScanReportDTO> getScanHistory() {
        return fs.getAllScans()
                 .stream()
                 .map(ScanReportDTO::fromEntity)
                 .collect(Collectors.toList());
    }

    @GetMapping("/history/{id}")
    public ScanReportDTO getScanById(@PathVariable Long id) {
        return ScanReportDTO.fromEntity(fs.getScanById(id));
    }

    @DeleteMapping("/history/{id}")
    public String deleteScan(@PathVariable Long id) {
        fs.deleteScan(id);
        return "Scan deleted successfully";
    }
}