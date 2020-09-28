package com.pansource.workflows.camundasso.auth;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationProvider;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.webapp.impl.security.auth.Authentications;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;

public class CamundaAuthProvider implements AuthenticationProvider {

    private static final String USER_ID = "Camunda User";

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest httpServletRequest, ProcessEngine processEngine) {
        Authentications authentications = Authentications.getFromSession(httpServletRequest.getSession());
        String userId = USER_ID;
        if(authentications != null && authentications.hasAuthenticationForProcessEngine(processEngine.getName())) {
            userId = authentications.getAuthenticationForProcessEngine(processEngine.getName()).getName();
        }
        AuthenticationResult authenticationResult = new AuthenticationResult(userId, true);
        authenticationResult.setGroups(new ArrayList<>());
        return authenticationResult;
    }

    @Override
    public void augmentResponseByAuthenticationChallenge(HttpServletResponse httpServletResponse, ProcessEngine processEngine) {

    }
}
