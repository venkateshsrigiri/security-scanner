package com.scanner.security.util;

import org.apache.tika.Tika;
import org.springframework.web.multipart.MultipartFile;

public class FileExtractor {

    public String extractText(MultipartFile file) {
        Tika tika = new Tika();

        try {
            return tika.parseToString(file.getInputStream());
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract the file content");
        }
    }
}