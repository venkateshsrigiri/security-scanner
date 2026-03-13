package com.scanner.security.scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SensitiveDataScanner {

    public List<String> scanSensitiveWords(String words){
        List<String> findings = new ArrayList<>();
        Pattern emailPattern = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
        Pattern cardPattern = Pattern.compile("\\b\\d{16}\\b");
        Matcher emailMatcher = emailPattern.matcher(words);
        Matcher cardMatcher = cardPattern.matcher(words);

        if(emailMatcher.find()){
            findings.add("Sensitive email detected");
        }
        if(cardMatcher.find()){
            findings.add("Possible credit card number detected");
        }
        return findings;
    }
        
        
    
    

    
}
