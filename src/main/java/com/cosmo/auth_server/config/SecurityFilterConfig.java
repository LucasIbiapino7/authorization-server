package com.cosmo.auth_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class SecurityFilterConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        //Ativa as configs básicas do OAuth para esse Auth Server
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Obtém a instância do configurador para configurar o OIDC
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        // Configura o tratamento de exceções e o recurso de autenticação via JWT
        http
                .exceptionHandling((exception) -> exception.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login"))) // Redireciona pro endpoint
                // de login quando nao esta logado
                        .oauth2ResourceServer((resource) -> resource.jwt(Customizer.withDefaults())); // Aceita
                // endpoints extras
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((auth) -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
        ;
        return http.build();
    }
}
