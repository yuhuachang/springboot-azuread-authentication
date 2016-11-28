package com.example;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.microsoft.aad.adal4j.UserInfo;

@RestController
public class MyController {

    @RequestMapping("/")
    public String hello(HttpServletRequest request) {
        
        UserInfo p = (UserInfo) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        
        return "Hello " + p.getDisplayableId() + " from " + request.getRemoteAddr();
    }
}
