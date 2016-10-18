/*******************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 * 
 * All Rights Reserved
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 * 
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 ******************************************************************************/
package com.example;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;

@Component
public class AzureADAuthenticationFilter extends OncePerRequestFilter {

    private static Logger log = LoggerFactory.getLogger(AzureADAuthenticationFilter.class);

    @Value("${com.example.authority}")
    private String authority;

    @Value("${com.example.tenant}")
    private String tenant;

    @Value("${com.example.clientId}")
    private String clientId;
    
    @Value("${com.example.clientSecret}")
    private String clientSecret;

    @Value("${com.example.logout}")
    private String logout;

    @Value("${com.example.error}")
    private String error;

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(authority);
        Assert.notNull(tenant);
        Assert.notNull(clientId);
        Assert.notNull(clientSecret);
        Assert.notNull(logout);
        Assert.notNull(error);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException { 
        try {

            String currentUri = AuthHelper.getCurrentUri(request);

            // Check if current session contains user authentication info.
            if (!AuthHelper.isAuthenticated(request)) {

                if (log.isTraceEnabled()) {
                    log.trace("AuthHelper.isAuthenticated = false");
                }

                if (AuthHelper.containsAuthenticationData(request)) {
                    // The request contains authentication data, which means this request is returned from AzureAD login page
                    // after authentication process is completed.  The result should have been processed by AzureADResponseFilter.
                } else {
                    if (log.isTraceEnabled()) {
                        log.trace("AuthHelper.containsAuthenticationData = false");
                    }

                    // when not authenticated and request does not contains authentication data (not come from Azure AD login process),
                    // redirect to Azure login page.
                    
                    // get csrf token
                    CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
                    if (log.isDebugEnabled()) {
                        log.debug("Current csrf token before going to AzureAD login {} {} = {}", token.getHeaderName(), token.getParameterName(), token.getToken());
                    }

                    // add the csrf token to login request and go login...
                    response.setStatus(302);
                    String redirectTo = getRedirectUrl(currentUri) + "&state=" + token.getToken();

                    if (log.isDebugEnabled()) {
                        log.debug("302 redirect to " + redirectTo);
                    }
                    response.sendRedirect(redirectTo);
                    return;
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("AuthHelper.isAuthenticated = true");
                }

                // if authenticated, how to check for valid session?
                AuthenticationResult result = AuthHelper.getAuthSessionObject(request);

                if (request.getParameter("refresh") != null) {
                    result = getAccessTokenFromRefreshToken(result.getRefreshToken(), currentUri);
                } else {
                    if (request.getParameter("cc") != null) {
                        result = getAccessTokenFromClientCredentials();
                    } else {
                        if (result.getExpiresOnDate().before(new Date())) {
                            result = getAccessTokenFromRefreshToken(result.getRefreshToken(), currentUri);
                        }
                    }
                }
                
                AuthHelper.setAuthSessionObject(request, result);
                
                // Handle logout
                if (logout.equals(request.getRequestURI())) {
                    if (log.isTraceEnabled()) {
                        log.trace("Logout...");
                    }
                    
                    // Clear spring security context so spring thinks this user is gone.
                    request.logout();
                    SecurityContextHolder.clearContext();

                    // Clear Azure principal
                    AuthHelper.remoteAuthSessionObject(request);
                    
                    // Go to AzureAD and logout.
                    response.setStatus(302);
                    String logoutPage = "https://login.windows.net/" + tenant + "/oauth2/logout";
                    if (log.isDebugEnabled()) {
                        log.debug("302 redirect to " + logoutPage);
                    }
                    
                    response.sendRedirect(logoutPage);
                    return;
                } else {
                    if (log.isTraceEnabled()) {
                        log.trace("URI: " + request.getRequestURI() + " does not match " + logout + ".  It is not a logout request");
                    }
                }
            }
        } catch (Throwable exc) {
            response.setStatus(500);
            request.setAttribute("error", exc.getMessage());
            response.sendRedirect(((HttpServletRequest) request).getContextPath() + error);
        }
        
        filterChain.doFilter(request, response);
    }

    private AuthenticationResult getAccessTokenFromClientCredentials() throws Throwable {
        AuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authority + tenant + "/", true, service);
            Future<AuthenticationResult> future = context.acquireToken("https://graph.windows.net",
                    new ClientCredential(clientId, clientSecret), null);
            result = future.get();
        } catch (ExecutionException e) {
            throw e.getCause();
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new ServiceUnavailableException("authentication result was null");
        }
        return result;
    }

    private AuthenticationResult getAccessTokenFromRefreshToken(String refreshToken, String currentUri)
            throws Throwable {
        AuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authority + tenant + "/", true, service);
            Future<AuthenticationResult> future = context.acquireTokenByRefreshToken(refreshToken,
                    new ClientCredential(clientId, clientSecret), null, null);
            result = future.get();
        } catch (ExecutionException e) {
            throw e.getCause();
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new ServiceUnavailableException("authentication result was null");
        }
        return result;

    }

    private String getRedirectUrl(String currentUri) throws UnsupportedEncodingException {
        String redirectUrl = authority + tenant
                + "/oauth2/authorize?response_type=code%20id_token&scope=openid&response_mode=form_post&redirect_uri="
                + URLEncoder.encode(currentUri, "UTF-8") + "&client_id=" + clientId
                + "&resource=https%3a%2f%2fgraph.windows.net" + "&nonce=" + UUID.randomUUID() + "&site_id=500879";
        return redirectUrl;
    }

}
