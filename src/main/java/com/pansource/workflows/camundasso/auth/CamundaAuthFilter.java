package com.pansource.workflows.camundasso.auth;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationProvider;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.webapp.impl.security.auth.Authentication;
import org.camunda.bpm.webapp.impl.security.auth.AuthenticationService;
import org.camunda.bpm.webapp.impl.security.auth.Authentications;
import org.camunda.bpm.webapp.impl.util.ProcessEngineUtil;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Modified copy of ContainerBasedAuthenticationFilter.java
 * @see org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter
 */
public class CamundaAuthFilter implements Filter {
    public static Pattern APP_PATTERN = Pattern.compile("/app/(cockpit|admin|tasklist|welcome)/([^/]+)/");
    public static Pattern API_ENGINE_PATTERN = Pattern.compile("/api/engine/engine/([^/]+)/.*");
    public static Pattern API_STATIC_PLUGIN_PATTERN = Pattern.compile("/api/(cockpit|admin|tasklist|welcome)/plugin/[^/]+/static/.*");
    public static Pattern API_PLUGIN_PATTERN = Pattern.compile("/api/(cockpit|admin|tasklist|welcome)/plugin/[^/]+/([^/]+)/.*");
    protected AuthenticationProvider authenticationProvider;
    protected AuthenticationService userAuthentications;

    private CamundaAuthzService camundaAuthzService;
    public CamundaAuthFilter() {
        camundaAuthzService = new CamundaAuthzService();
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        this.userAuthentications = new AuthenticationService();
        String authenticationProviderClassName = filterConfig.getInitParameter("authentication-provider");
        if (authenticationProviderClassName == null) {
            throw new ServletException("Cannot instantiate authentication filter: no authentication provider set. init-param authentication-provider missing");
        } else {
            try {
                Class<?> authenticationProviderClass = Class.forName(authenticationProviderClassName);
                this.authenticationProvider = (AuthenticationProvider)authenticationProviderClass.newInstance();
            } catch (ClassNotFoundException var4) {
                throw new ServletException("Cannot instantiate authentication filter: authentication provider not found", var4);
            } catch (InstantiationException var5) {
                throw new ServletException("Cannot instantiate authentication filter: cannot instantiate authentication provider", var5);
            } catch (IllegalAccessException var6) {
                throw new ServletException("Cannot instantiate authentication filter: constructor not accessible", var6);
            } catch (ClassCastException var7) {
                throw new ServletException("Cannot instantiate authentication filter: authentication provider does not implement interface " + AuthenticationProvider.class.getName(), var7);
            }
        }
    }

    public void destroy() {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse resp = (HttpServletResponse)response;
        String engineName = this.extractEngineName(req);
        if (engineName == null) {
            chain.doFilter(request, response);
        } else {
            ProcessEngine engine = this.getAddressedEngine(engineName);
            if (engine == null) {
                resp.sendError(404, "Process engine " + engineName + " not available");
            } else {
                AuthenticationResult authenticationResult = this.authenticationProvider.extractAuthenticatedUser(req, engine);
                if (authenticationResult.isAuthenticated()) {
                    Authentications authentications = Authentications.getFromSession(req.getSession());
                    String authenticatedUser = authenticationResult.getAuthenticatedUser();
                    if (!this.existisAuthentication(authentications, engineName, authenticatedUser)) {
                        List<String> groups = authenticationResult.getGroups();
                        List<String> tenants = authenticationResult.getTenants();
                        camundaAuthzService.addAuthorization(authenticatedUser, engine.getAuthorizationService());
                        Authentication authentication = this.createAuthentication(engine, authenticatedUser, groups, tenants);
                        authentications.addAuthentication(authentication);
                    }

                    chain.doFilter(request, response);
                } else {
                    resp.setStatus(Response.Status.UNAUTHORIZED.getStatusCode());
                    this.authenticationProvider.augmentResponseByAuthenticationChallenge(resp, engine);
                }

            }
        }
    }

    protected String getRequestUri(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return request.getRequestURI().substring(contextPath.length());
    }

    protected String extractEngineName(HttpServletRequest request) {
        String requestUri = this.getRequestUri(request);
        String requestMethod = request.getMethod();
        Matcher appMatcher = APP_PATTERN.matcher(requestUri);
        if (appMatcher.matches()) {
            return appMatcher.group(2);
        } else {
            Matcher apiEngineMatcher = API_ENGINE_PATTERN.matcher(requestUri);
            if (apiEngineMatcher.matches()) {
                return apiEngineMatcher.group(1);
            } else {
                Matcher apiStaticPluginPattern = API_STATIC_PLUGIN_PATTERN.matcher(requestUri);
                if (requestMethod.equals("GET") && apiStaticPluginPattern.matches()) {
                    return null;
                } else {
                    Matcher apiPluginPattern = API_PLUGIN_PATTERN.matcher(requestUri);
                    return apiPluginPattern.matches() ? apiPluginPattern.group(2) : null;
                }
            }
        }
    }

    protected ProcessEngine getAddressedEngine(String engineName) {
        return ProcessEngineUtil.lookupProcessEngine(engineName);
    }

    protected boolean existisAuthentication(Authentications authentications, String engineName, String username) {
        Authentication authentication = authentications.getAuthenticationForProcessEngine(engineName);
        return authentication != null && this.isAuthenticated(authentication, engineName, username);
    }

    protected boolean isAuthenticated(Authentication authentication, String engineName, String username) {
        String processEngineName = authentication.getProcessEngineName();
        String identityId = authentication.getIdentityId();
        return processEngineName.equals(engineName) && identityId.equals(username);
    }

    protected Authentication createAuthentication(ProcessEngine processEngine, String username, List<String> groups, List<String> tenants) {
        return this.userAuthentications.createAuthenticate(processEngine, username, groups, tenants);
    }
}
