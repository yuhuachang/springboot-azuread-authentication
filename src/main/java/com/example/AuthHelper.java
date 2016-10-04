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

import javax.servlet.http.HttpServletRequest;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

public final class AuthHelper {

    public static final String PRINCIPAL_SESSION_NAME = "principal";
    
    public static final String ERROR = "error";
//    public static final String ERROR_DESCRIPTION = "error_description";
//    public static final String ERROR_URI = "error_uri";
    public static final String ID_TOKEN = "id_token";
    public static final String CODE = "code";

    public static boolean isAuthenticated(HttpServletRequest request) {
        return request.getSession().getAttribute(PRINCIPAL_SESSION_NAME) != null;
    }

    public static AuthenticationResult getAuthSessionObject(HttpServletRequest request) {
        return (AuthenticationResult) request.getSession().getAttribute(PRINCIPAL_SESSION_NAME);
    }

    public static void setAuthSessionObject(HttpServletRequest request, AuthenticationResult result) {
        request.getSession().setAttribute(AuthHelper.PRINCIPAL_SESSION_NAME, result);
    }
    
    public static void remoteAuthSessionObject(HttpServletRequest request) {
        request.getSession().removeAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
    }

    public static boolean containsAuthenticationData(HttpServletRequest request) {
        return request.getMethod().equalsIgnoreCase("POST")
                && (request.getParameterMap().containsKey(ERROR)
                        || request.getParameterMap().containsKey(ID_TOKEN)
                        || request.getParameterMap().containsKey(CODE));
    }

    public static boolean isAuthenticationSuccessful(AuthenticationResponse authResponse) {
        return authResponse instanceof AuthenticationSuccessResponse;
    }

}
