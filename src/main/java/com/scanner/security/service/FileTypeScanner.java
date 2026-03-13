package com.scanner.security.service;

import java.util.ArrayList;
import java.util.List;

public class FileTypeScanner {
    public List<String> scanFileType(String fileName){
        List<String> findings = new ArrayList<>();
        if(fileName.endsWith(".exe")||fileName.endsWith(".bat")||fileName.endsWith(".js")){
            findings.add("Dangerous file type detected");
        }
        return findings;
    }
    
}
