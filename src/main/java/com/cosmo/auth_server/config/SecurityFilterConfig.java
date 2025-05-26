package com.cosmo.auth_server.config;

import com.cosmo.auth_server.services.CustomOidcUserService;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityFilterConfig {

    @Value("${cors.config.allowed-origin}")
    private String corsOrigin;

    @Bean
    @Order(1)
    SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        //Ativa as configs básicas do OAuth para esse Auth Server
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Obtém a instância do configurador para configurar o OIDC
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        http
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .formLogin(form -> form.loginPage("/login").permitAll())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        // Configura o tratamento de exceções e o recurso de autenticação via JWT
        http.oauth2ResourceServer((resource) -> resource.jwt(Customizer.withDefaults())); // Aceita endpoints extras
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, CustomOidcUserService oidcUserService) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/auth/register")
                        .permitAll().anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .userInfoEndpoint(info -> info.oidcUserService(oidcUserService))
                )
                .cors((cors) -> cors.configurationSource(corsConfigurationSource()))
        ;
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(corsOrigin));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setExposedHeaders(List.of("Authorization"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
