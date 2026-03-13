package com.scanner.security.scanner;

import java.util.ArrayList;
import java.util.List;

public class KeyWordsScanner {

    public List<String> scanKeywords(String words){
        List<String> susWords = List.of(
            "password",
            "secret",
            "token",
            "api_key",
            "confidential",
            "private_key"
        );
        List<String> findings = new ArrayList<>();
        for(String words1 : susWords){
            if(words.toLowerCase().contains(words1.toLowerCase())){
                findings.add("Suspicious words have been found:"+ words1);
            }

        }

        return findings;
    }


    
}
