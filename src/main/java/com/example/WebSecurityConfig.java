package com.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;

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
        
        // Add AzureAD filter before and after CsrfFilter
        http.addFilterBefore(new AzureADResponseFilter(), CsrfFilter.class);
        http.addFilterAfter(new AzureADAuthenticationFilter(), CsrfFilter.class);
        
        http.authorizeRequests().anyRequest().authenticated();
    }
}