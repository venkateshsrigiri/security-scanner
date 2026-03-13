package com.scanner.security.service;

import java.util.ArrayList;
import java.util.List;

public class ScriptScanner {
    public List<String> scanScripts(String content){
        List<String> findings = new ArrayList<>();
        if(content.contains("<script>")){
            findings.add("Embedded script detected");
        }
        if(content.contains("eval")){
            findings.add("Potential malicious script pattern detected");
        }
        if(content.contains("cmd.exe")){
            findings.add("Command execution pattern detected");
        }
        return findings;
        
    }
}
