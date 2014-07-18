package com.ethlo.security.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

/**
 * The problem with using BASIC authentication is that we do not want a browser authentication window when using 
 * a JavaScript client, but we still want to be compatible for standard integration purposes, so we rely on a 
 * special header to trigger a custom WWW-Authenticate header that is not recognized by browsers.
 * 
 * @author Morten Haraldsen
 */
public class ConfigurableAuthChallengeBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint
{
    private String customAuthenticateTriggerHeader = "X-NoAuthChallenge";
    private String customAuthenticateResponseHeader = "javascript-basic";
    private boolean exposeErrorReason = false;
    private String errorReasonHeader = "X-Auth-Error";
	
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException 
	{
		if (request.getHeader(customAuthenticateTriggerHeader) == null)
		{
			super.commence(request, response, authException);
		}
		else
		{
			if (exposeErrorReason)
			{
			    response.setHeader(errorReasonHeader, authException.getClass().getSimpleName());
			}
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			response.addHeader("WWW-Authenticate", customAuthenticateResponseHeader);
		}
	}

    public String getCustomAuthenticateTriggerHeader()
    {
        return customAuthenticateTriggerHeader;
    }

    public void setCustomAuthenticateTriggerHeader(String customAuthenticateTriggerHeader)
    {
        this.customAuthenticateTriggerHeader = customAuthenticateTriggerHeader;
    }

    public String getCustomAuthenticateResponseHeader()
    {
        return customAuthenticateResponseHeader;
    }

    public void setCustomAuthenticateResponseHeader(String customAuthenticateResponseHeader)
    {
        this.customAuthenticateResponseHeader = customAuthenticateResponseHeader;
    }

    public boolean isExposeErrorReason()
    {
        return exposeErrorReason;
    }

    public void setExposeErrorReason(boolean exposeErrorReason)
    {
        this.exposeErrorReason = exposeErrorReason;
    }

    public String getErrorReasonHeader()
    {
        return errorReasonHeader;
    }

    public void setErrorReasonHeader(String errorReasonHeader)
    {
        this.errorReasonHeader = errorReasonHeader;
    }
}