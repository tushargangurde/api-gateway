package com.tushar.lms.apigateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

@Configuration
public class CustomAuthorizationFilter implements GlobalFilter {

	Logger logger = LoggerFactory.getLogger(CustomAuthorizationFilter.class);

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

		ServerHttpRequest request = exchange.getRequest();
		ServerHttpResponse response = exchange.getResponse();

		String requestPath = request.getPath().toString();

		logger.info("Request Path:" + requestPath);

		if (requestPath.equals("/user/add") || requestPath.equals("/login")) {
			return chain.filter(exchange);
		} else {

			String authorizationHeader = request.getHeaders().getFirst("Authorization");

			if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer")) {
				logger.info("Authorization header is empty or does not start with Bearer");
				response.setStatusCode(HttpStatus.UNAUTHORIZED);
				return response.setComplete();
			}

			String token = authorizationHeader.replace("Bearer ", "");

			String userId = Jwts.parser().setSigningKey("secret_key").parseClaimsJws(token).getBody().getSubject();

			if (userId == null) {
				logger.info("User Id not present in the JWT");
				response.setStatusCode(HttpStatus.UNAUTHORIZED);
				return response.setComplete();
			}

			return chain.filter(exchange);
		}
	}

}
