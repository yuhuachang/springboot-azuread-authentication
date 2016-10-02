package com.example;

import java.util.Map;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.View;

import com.microsoft.aad.adal4j.UserInfo;

@Controller
public class MyController {

    @RequestMapping("/")
    public View myHome() {
        return new View() {
            @Override
            public String getContentType() {
                return MediaType.TEXT_HTML_VALUE;
            }
            @Override
            public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response)
                    throws Exception {
                ServletOutputStream out = response.getOutputStream();
                
                UserInfo p = (UserInfo) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

                out.println("<!DOCTYPE html>");
                out.println("<html>");
                out.println("  <head>");
                out.println("    <meta charset=\"UTF-8\">");
                out.println("  </head>");
                out.println("  <body>");
                out.println("    Hello " + p.getDisplayableId() + "<br />");
                out.println("    <a href=\"/logout\">logout</a><br />");
                out.println("  </body>");
                out.println("</html>");
                out.flush();
                out.close();
            }
        };
    }
    
    @RequestMapping("/service")
    @ResponseBody
    public String myService() {
        
        UserInfo p = (UserInfo) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return "Hello " + p.getDisplayableId();
    }
}
