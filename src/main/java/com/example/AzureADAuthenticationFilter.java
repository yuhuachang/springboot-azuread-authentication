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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;

public class AzureADAuthenticationFilter extends OncePerRequestFilter {

    private static Logger log = LoggerFactory.getLogger(AzureADAuthenticationFilter.class);

    public static final String clientId = "cf7e14a9-f6d4-45a4-8bdb-7b67efd55745";
    public static final String clientSecret = "yy72A9TlHwU4PlqoDFUAg2lBpxgCD5ugTOFm4nIMp10=";
    public static final String tenant = "57e289b5-527b-4356-b8cd-d990c1875a1b";
    public static final String authority = "https://login.microsoftonline.com/";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {

            String currentUri = request.getScheme() + "://" + request.getServerName()
                    + ("http".equals(request.getScheme()) && request.getServerPort() == 80
                            || "https".equals(request.getScheme()) && request.getServerPort() == 443 ? ""
                                    : ":" + request.getServerPort())
                    + request.getRequestURI();

            // check if user has a session
            if (!AuthHelper.isAuthenticated(request)) {

                log.info("AuthHelper.isAuthenticated = false");

                if (AuthHelper.containsAuthenticationData(request)) {
                    // handled previously already...
                } else {
                    log.info("AuthHelper.containsAuthenticationData = false");

                    // when not authenticated and request does not contains authentication data (not come from Azure AD login process),
                    // redirect to Azure login page.
                    
                    // get csrf token
                    CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
                    log.info("current csrf token before going to AzureAD login {} {} = {}", token.getHeaderName(), token.getParameterName(), token.getToken());
                    
                    // add the csrf token to login request and go login...
                    response.setStatus(302);
                    String redirectTo = getRedirectUrl(currentUri);
                    redirectTo += "&state=" + token.getToken();

                    log.info("302 redirect to " + redirectTo);
                    
                    response.sendRedirect(redirectTo);
                    return;
                }
            } else {
                log.info("AuthHelper.isAuthenticated = true");

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
                createSessionPrincipal(request, result);
                
                // handle logout
                log.info("URI: " + request.getRequestURI());
                if ("/logout".equals(request.getRequestURI())) {
                    log.info("logout...");
                    
                    // clear spring security context so spring thinks this user is gone.
                    request.logout();
                    SecurityContextHolder.clearContext();

                    // clear Azure principal
                    request.getSession().setAttribute(AuthHelper.PRINCIPAL_SESSION_NAME, null);
                    
                    // go to AzureAD and logout.
                    response.setStatus(302);
                    //String logoutPage = "https://login.windows.net/" + BasicFilter.tenant + "/oauth2/logout?post_logout_redirect_uri=https://login.windows.net/";
                    String logoutPage = "https://login.windows.net/" + AzureADAuthenticationFilter.tenant + "/oauth2/logout";
                    log.info("302 redirect to " + logoutPage);
                    
                    response.sendRedirect(logoutPage);
                    return;
                }
            }
        } catch (Throwable exc) {
            response.setStatus(500);
            request.setAttribute("error", exc.getMessage());
            response.sendRedirect(((HttpServletRequest) request).getContextPath() + "/error.jsp");
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

    private void createSessionPrincipal(HttpServletRequest httpRequest, AuthenticationResult result) throws Exception {
        
        log.info("create session principal: " + result.getUserInfo().getDisplayableId());
        
        httpRequest.getSession().setAttribute(AuthHelper.PRINCIPAL_SESSION_NAME, result);
    }

    private String getRedirectUrl(String currentUri) throws UnsupportedEncodingException {
        String redirectUrl = authority + tenant
                + "/oauth2/authorize?response_type=code%20id_token&scope=openid&response_mode=form_post&redirect_uri="
                + URLEncoder.encode(currentUri, "UTF-8") + "&client_id=" + clientId
                + "&resource=https%3a%2f%2fgraph.windows.net" + "&nonce=" + UUID.randomUUID() + "&site_id=500879";
        return redirectUrl;
    }

}
