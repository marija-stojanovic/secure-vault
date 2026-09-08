package com.securevault.config;

import com.securevault.auth.CookieAuthenticationFilter;
import com.securevault.auth.oidc.InMemoryAuthorizationRequestRepository;
import com.securevault.auth.oidc.OidcAuthenticationFailureHandler;
import com.securevault.auth.oidc.OidcAuthenticationSuccessHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            CookieAuthenticationFilter cookieAuthenticationFilter,
            ObjectProvider<ClientRegistrationRepository> clientRegistrations,
            InMemoryAuthorizationRequestRepository authorizationRequestRepository,
            OidcAuthenticationSuccessHandler oidcSuccessHandler,
            OidcAuthenticationFailureHandler oidcFailureHandler
    ) throws Exception {
        CookieCsrfTokenRepository csrfTokenRepository =
                CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfTokenRepository.setCookieCustomizer(cookie -> cookie
                .secure(true)
                .sameSite("Strict")
                .path("/"));

        http
                .cors(cors -> cors.disable())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                        .ignoringRequestMatchers("/api/auth/**"))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, exception) ->
                                response.sendError(HttpStatus.UNAUTHORIZED.value())))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/api/health",
                                "/api/security-policy/public",
                                "/actuator/health",
                                "/api/auth/register",
                                "/api/auth/oidc/setup",
                                "/api/auth/oidc/mfa",
                                "/api/auth/mfa/confirm",
                                "/api/auth/login/password",
                                "/api/auth/login/mfa",
                                "/api/auth/refresh",
                                "/api/auth/logout",
                                "/oauth2/**",
                                "/login/oauth2/**"
                        ).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/sharing/received").hasRole("DEVELOPER")
                        .requestMatchers("/api/sharing/**").hasRole("TEAM_LEAD")
                        .anyRequest().authenticated())
                .addFilterBefore(cookieAuthenticationFilter, AnonymousAuthenticationFilter.class);

        ClientRegistrationRepository registrations = clientRegistrations.getIfAvailable();
        if (registrations != null) {
            DefaultOAuth2AuthorizationRequestResolver requestResolver =
                    new DefaultOAuth2AuthorizationRequestResolver(
                            registrations,
                            "/oauth2/authorization"
                    );
            requestResolver.setAuthorizationRequestCustomizer(customizer ->
                    customizer.additionalParameters(parameters ->
                            parameters.put("prompt", "select_account")));

            http.oauth2Login(oauth -> oauth
                    .authorizationEndpoint(endpoint -> endpoint
                            .authorizationRequestResolver(requestResolver)
                            .authorizationRequestRepository(authorizationRequestRepository))
                    .successHandler(oidcSuccessHandler)
                    .failureHandler(oidcFailureHandler));
        }

        return http.build();
    }
}
