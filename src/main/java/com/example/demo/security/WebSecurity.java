package com.example.demo.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@Slf4j
public class WebSecurity {

    @Autowired
    private JwtToUserConverter jwtToUserConverter;

    @Autowired
    private KeyUtils keyUtils;


    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated())
                .csrf().disable()
                .cors().disable()
                .httpBasic().disable()
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtToUserConverter))
                )
                .sessionManagement(session ->  session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling((exceptions) ->  exceptions
                                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                                .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                        );
    return http.build();
    }

    @Bean
    @Primary
    public JwtDecoder jwtAccessTokenDecoder (){
        return NimbusJwtDecoder.withPublicKey(keyUtils.getAccessTokenPublicKey()).build();
    }
    @Bean
    @Primary
    public JwtEncoder jwtAccessTokenEncoder(){
        JWK jwk = new RSAKey
                .Builder(keyUtils.getAccessTokenPublicKey())
                .privateKey(keyUtils.getAccessTokenPrivateKey())
                .build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    @Qualifier("jwtRefreshTokenDecoder")
    public JwtDecoder jwtRefreshTokenDecoder (){
        return NimbusJwtDecoder.withPublicKey(keyUtils.getRefreshTokenPublicKey()).build();
    }

    @Bean
    @Qualifier("jwtRefreshTokenEncoder")
    public JwtEncoder jwtRefreshTokenEncoder(){
        JWK jwk = new RSAKey
                .Builder(keyUtils.getRefreshTokenPublicKey())
                .privateKey(keyUtils.getRefreshTokenPrivateKey())
                .build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    @Qualifier("jwtRefreshTokenAuthProvider")
    JwtAuthenticationProvider jwtRefreshTokenAuthProvider (){
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtRefreshTokenDecoder());
        provider.setJwtAuthenticationConverter(jwtToUserConverter);
        return provider;
    }
}
