package com.cosmo.auth_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class ClientStoreConfig {

    @Value("${security.client-id}")
    private String clientId;

    @Value("${security.redirect-uri}")
    private String redirectUrl;

    @Value("${security.post-logout-redirect-uri}")
    private String logoutUrl;

    @Value("${security.jwt.duration}")
    private long jwtDuration;

    @Bean
    RegisteredClientRepository registeredClientRepository(DataSource dataSource) {

        JdbcRegisteredClientRepository jdbcRepo =
                new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));

        // Se ainda não existir, cria o SPA
        if (jdbcRepo.findByClientId(clientId) == null) {

            RegisteredClient spa = RegisteredClient
                    .withId(UUID.randomUUID().toString())
                    .clientId(clientId)                 // ex.: gerenciador-spa
                    .clientName("Gerenciador SPA")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri(redirectUrl)
                    .postLogoutRedirectUri(logoutUrl)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .requireProofKey(true)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofSeconds(jwtDuration))
                            .refreshTokenTimeToLive(Duration.ofDays(30))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();

            jdbcRepo.save(spa);
        }

        return jdbcRepo;
    }
}
