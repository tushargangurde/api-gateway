package com.tushar.lms.apigateway.security;

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import reactor.core.publisher.Flux;
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
				return Mono.defer(() -> {
					response.setStatusCode(HttpStatus.UNAUTHORIZED);// Set status

					byte[] bytes = "No token present".getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(bytes);
					logger.info("No token present");
					return response.writeWith(Flux.just(buffer));// Set body
				});

			}

			String token = authorizationHeader.replace("Bearer ", "");
			String userId = null;
			
			try {
				userId = Jwts.parser().setSigningKey("secret_key").parseClaimsJws(token).getBody().getSubject();
			} catch (ExpiredJwtException exception) {
				return Mono.defer(() -> {
					response.setStatusCode(HttpStatus.UNAUTHORIZED);// Set status
					byte[] bytes = "JWT Token Expired".getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(bytes);
					logger.info("JWT Token Expired");
					return response.writeWith(Flux.just(buffer));// Set body
				});
			} catch (SignatureException exception) {
				return Mono.defer(() -> {
					response.setStatusCode(HttpStatus.UNAUTHORIZED);// Set status
					byte[] bytes = "JWT signature does not match".getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(bytes);
					logger.info("JWT signature does not match");
					return response.writeWith(Flux.just(buffer));// Set body
				});
			} catch (Exception exception) {
				return Mono.defer(() -> {
					response.setStatusCode(HttpStatus.UNAUTHORIZED);// Set status
					byte[] bytes = ("JWT related exception. " + exception.getMessage())
							.getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(bytes);
					logger.info(exception.getMessage());
					return response.writeWith(Flux.just(buffer));// Set body
				});
			}

			if (userId == null) {
				return Mono.defer(() -> {
					response.setStatusCode(HttpStatus.UNAUTHORIZED);// Set status

					byte[] bytes = "User Id is not present".getBytes(StandardCharsets.UTF_8);
					DataBuffer buffer = response.bufferFactory().wrap(bytes);
					logger.info("User Id is not present");
					return response.writeWith(Flux.just(buffer));// Set body
				});
			}

			return chain.filter(exchange);
		}
	}

}
