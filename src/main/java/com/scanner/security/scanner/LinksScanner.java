package com.scanner.security.scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LinksScanner {

    public List<String> scanLinks(String content){
        List<String> findings = new ArrayList<>();
        Pattern urlPattern = Pattern.compile("(https?://\\S+)");
        Matcher matcher = urlPattern.matcher(content);

        while(matcher.find()){
            String url = matcher.group();
            findings.add("Suspicious links found: "+ url);

        }
        return findings;
    }
    
}
