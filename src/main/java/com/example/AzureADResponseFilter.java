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
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

@Component
public class AzureADResponseFilter extends OncePerRequestFilter {

    private static Logger log = LoggerFactory.getLogger(AzureADResponseFilter.class);

    @Value("${com.example.authority}")
    private String authority;

    @Value("${com.example.tenant}")
    private String tenant;

    @Value("${com.example.clientId}")
    private String clientId;
    
    @Value("${com.example.clientSecret}")
    private String clientSecret;

    @Value("${com.example.error}")
    private String error;

    private String csrfToken;
    
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(authority);
        Assert.notNull(tenant);
        Assert.notNull(clientId);
        Assert.notNull(clientSecret);
        Assert.notNull(error);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {

            String currentUri = AuthHelper.getCurrentUri(request);

            csrfToken = null;

            // check if user has a session
            if (!AuthHelper.isAuthenticated(request) && AuthHelper.containsAuthenticationData(request)) {

                // The current session does not have the authentication info and the request contains the authentication data.
                // This request comes from AzureAD login page after login process is completed.

                if (log.isTraceEnabled()) {
                    log.trace("AuthHelper.isAuthenticated = false && AuthHelper.containsAuthenticationData = true");
                }
                
                Map<String, String> params = new HashMap<String, String>();
                for (String key : request.getParameterMap().keySet()) {
                    params.put(key, request.getParameterMap().get(key)[0]);
                }

                String fullUrl = currentUri + (request.getQueryString() != null ? "?" + request.getQueryString() : "");
                if (log.isTraceEnabled()) {
                    log.trace("URL: " + fullUrl);
                }
                
                AuthenticationResponse authResponse = AuthenticationResponseParser.parse(new URI(fullUrl), params);
                if (log.isTraceEnabled()) {
                    log.trace("authResponse = " + authResponse);
                }

                if (AuthHelper.isAuthenticationSuccessful(authResponse)) {
                    if (log.isTraceEnabled()) {
                        log.trace("AuthHelper.isAuthenticationSuccessful = true");
                    }
                    
                    // Retrieve authentication response.
                    AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;
                    AuthenticationResult result = getAccessToken(oidcResponse.getAuthorizationCode(), currentUri);
                    
                    // Retrieve CSRF token (the state is our csrf token.)
                    if (log.isDebugEnabled()) {
                        log.debug("oidcResponse.getState() = " + oidcResponse.getState());
                    }
                    csrfToken = oidcResponse.getState().getValue();

                    // Store authenticated principal to spring security context holder.
                    Authentication anAuthentication = new PreAuthenticatedAuthenticationToken(result.getUserInfo(), null);
                    anAuthentication.setAuthenticated(true);
                    SecurityContextHolder.getContext().setAuthentication(anAuthentication);
                    
                    if (log.isDebugEnabled()) {
                        log.debug("SecurityContextHolder.getContext().getAuthentication() = " + SecurityContextHolder.getContext().getAuthentication());
                    }

                    // Store authentication data to current session.
                    AuthHelper.setAuthSessionObject(request, result);
                } else {
                    if (log.isTraceEnabled()) {
                        log.trace("AuthHelper.isAuthenticationSuccessful = false");
                    }

                    AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
                    throw new Exception(String.format("Request for auth code failed: %s - %s",
                            oidcResponse.getErrorObject().getCode(),
                            oidcResponse.getErrorObject().getDescription()));
                }
            }
        } catch (Throwable exc) {
            response.setStatus(500);
            request.setAttribute("error", exc.getMessage());
            response.sendRedirect(((HttpServletRequest) request).getContextPath() + error);
        }

        if (csrfToken != null) {
            // When csrf token is retrieved, create a dummy request and put this csrf token to the header.
            if (log.isDebugEnabled()) {
                log.debug("Create a dummy request and put csrf token in its header {}", csrfToken);
            }
            filterChain.doFilter(new HttpServletRequestWrapper(request) {
                @Override
                public String getHeader(String name) {
                    if ("X-CSRF-TOKEN".equals(name)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Read csrf token from request header: {}", csrfToken);
                        }
                        return csrfToken;
                    }
                    return super.getHeader(name);
                }
            }, response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private AuthenticationResult getAccessToken(AuthorizationCode authorizationCode, String currentUri)
            throws Throwable {
        String authCode = authorizationCode.getValue();
        ClientCredential credential = new ClientCredential(clientId, clientSecret);
        AuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authority + tenant + "/", true, service);
            Future<AuthenticationResult> future = context.acquireTokenByAuthorizationCode(authCode, new URI(currentUri),
                    credential, null);
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

}
