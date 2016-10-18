package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AzureADResponseFilter azureADResponseFilter;
    
    @Autowired
    private AzureADAuthenticationFilter azureADAuthenticationFilter;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Do AzureAD authentication after CsrfFilter.
        // If is not authenticated, attach the csrf token and redirect to AzureAD to login.
        http.addFilterAfter(azureADAuthenticationFilter, CsrfFilter.class);

        // Process AzureAD authentication result before CsrfFilter.
        // When the login process is done, check the result and attach the csrf token back before CsrfFilter.
        http.addFilterBefore(azureADResponseFilter, CsrfFilter.class);

        http.authorizeRequests().anyRequest().authenticated();
    }
}