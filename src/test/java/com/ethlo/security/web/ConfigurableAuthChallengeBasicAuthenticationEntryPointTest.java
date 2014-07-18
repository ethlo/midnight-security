package com.ethlo.security.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.fest.assertions.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;

public class ConfigurableAuthChallengeBasicAuthenticationEntryPointTest
{
    @Test
    public void testTriggerOfCustomHeader() throws IOException, ServletException
    {
        final ConfigurableAuthChallengeBasicAuthenticationEntryPoint entryPoint = new ConfigurableAuthChallengeBasicAuthenticationEntryPoint();
        entryPoint.setCustomAuthenticateTriggerHeader("trigger-me");
        entryPoint.setCustomAuthenticateResponseHeader("hello there stranger");
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("trigger-me", 1);
        final MockHttpServletResponse res = new MockHttpServletResponse();
        entryPoint.commence(req, res, new AuthenticationCredentialsNotFoundException("Sorry, need auth"));
        assertThat(res.getHeader("WWW-Authenticate")).isEqualTo("hello there stranger");
        assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    @Test
    public void testDefaultChallengeHeader() throws IOException, ServletException
    {
        final ConfigurableAuthChallengeBasicAuthenticationEntryPoint entryPoint = new ConfigurableAuthChallengeBasicAuthenticationEntryPoint();
        entryPoint.setCustomAuthenticateTriggerHeader("trigger-me");
        entryPoint.setCustomAuthenticateResponseHeader("hello there stranger");
        final MockHttpServletRequest req = new MockHttpServletRequest();
        final MockHttpServletResponse res = new MockHttpServletResponse();
        entryPoint.commence(req, res, new AuthenticationCredentialsNotFoundException("Sorry, need auth"));
        assertThat(res.getHeader("WWW-Authenticate")).isEqualTo("Basic realm=\"" + entryPoint.getRealmName() + "\"");
        assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    @Test
    public void testTriggerOfCustomHeaderWithErrorExposure() throws IOException, ServletException
    {
        final ConfigurableAuthChallengeBasicAuthenticationEntryPoint entryPoint = new ConfigurableAuthChallengeBasicAuthenticationEntryPoint();
        entryPoint.setCustomAuthenticateTriggerHeader("trigger-me");
        entryPoint.setCustomAuthenticateResponseHeader("hello there stranger");
        entryPoint.setExposeErrorReason(true);
        entryPoint.setErrorReasonHeader("Auth-Error");
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("trigger-me", 1);
        final MockHttpServletResponse res = new MockHttpServletResponse();
        entryPoint.commence(req, res, new AuthenticationCredentialsNotFoundException("Sorry, need auth"));
        assertThat(res.getHeader("WWW-Authenticate")).isEqualTo("hello there stranger");
        assertThat(res.getHeader("Auth-Error")).isEqualTo(AuthenticationCredentialsNotFoundException.class.getSimpleName());
    }
}
