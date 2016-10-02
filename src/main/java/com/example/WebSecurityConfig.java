package com.example;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
//        http.addFilterBefore(new OncePerRequestFilter() {
//            @Override
//            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
//                    FilterChain filterChain) throws ServletException, IOException {
//
//                log.info("check csrf token {}", request.getHeader("X-CSRF-HEADER"));
//                log.info("check csrf token {}", request.getParameter("_csrf"));
//
//                filterChain.doFilter(request, response);
//            }
//        }, CsrfFilter.class);
        

        
        //http.addFilterAfter(new BasicFilter(), AbstractPreAuthenticatedProcessingFilter.class);
        
        http.addFilterBefore(new FirstFilter(), CsrfFilter.class);
        http.addFilterAfter(new BasicFilter(), CsrfFilter.class);
        
        http.authorizeRequests().anyRequest().authenticated();
        
//        http.csrf().disable();
    }
}