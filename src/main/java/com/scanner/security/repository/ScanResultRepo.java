package com.scanner.security.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.scanner.security.model.ScanResult;

public interface ScanResultRepo extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findAllByOrderByTimestampDesc();
    
}
