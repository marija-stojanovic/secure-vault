package com.securevault.gateway;

import com.securevault.gateway.ratelimit.RateLimitGatewayFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RequestPredicates;
import org.springframework.web.servlet.function.RequestPredicate;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;

@Configuration
public class GatewayRoutes {

    @Bean
    RouterFunction<ServerResponse> backendRoutes(
            @Value("${app.gateway.backend-uri}") String backendUri,
            RateLimitGatewayFilter rateLimitFilter
    ) {
        RequestPredicate backendPaths = RequestPredicates.path("/api/**")
                .or(RequestPredicates.path("/oauth2/**"))
                .or(RequestPredicates.path("/login/oauth2/**"));

        return route("secure-vault-backend")
                .route(backendPaths, http())
                .before(uri(backendUri))
                .filter(rateLimitFilter::filter)
                .build();
    }
}
