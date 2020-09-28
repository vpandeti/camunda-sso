package com.pansource.workflows.camundasso.config;

import com.pansource.workflows.camundasso.auth.CamundaAuthFilter;
import com.pansource.workflows.camundasso.auth.CamundaAuthProvider;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;

@Configuration
public class WebSecurityConfig {

    @Bean
    public FilterRegistrationBean authFilter() {
        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
        filterRegistration.setFilter(new CamundaAuthFilter());
        filterRegistration.setInitParameters(Collections.singletonMap("authentication-provider", CamundaAuthProvider.class.getCanonicalName()));
        filterRegistration.addUrlPatterns("/app/*", "/api/*", "/lib/*"); // Camunda UI url patterns
        return filterRegistration;
    }
}
