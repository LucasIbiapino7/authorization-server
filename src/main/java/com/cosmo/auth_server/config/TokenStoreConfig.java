package com.cosmo.auth_server.config;

import com.cosmo.auth_server.enitities.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.apache.tomcat.util.file.ConfigurationSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
public class TokenStoreConfig {

    @Value("${security.jwk.location}")
    private Resource jwkLocation;
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // permite que o endpoint /.well-known/jwks.json exponha a chave pública para clientes validarem os tokens.
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = loadRsaKey();
        return (selector, ctx) -> selector.select(new JWKSet(rsaKey));
    }

    private RSAKey loadRsaKey() {
        try (InputStream in = jwkLocation.getInputStream()) {
            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            JWK jwk = JWK.parseFromPEMEncodedObjects(pem);
            if (!(jwk instanceof RSAKey rsa)) {
                throw new IllegalStateException("PEM is not an RSA key");
            }
            return new RSAKey.Builder(rsa)
                    .keyID("lab-key-1")
                    .build();
        } catch (IOException | JOSEException e) {
            throw new IllegalStateException("Failed to load RSA key", e);
        }
    }

    // usado pelo Spring para validar tokens automaticamente quando configurado com .oauth2ResourceServer().jwt().
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if ("access_token".equals(context.getTokenType().getValue())) {
                var principal = context.getPrincipal().getPrincipal();

                String username;
                String fullName;
                if (principal instanceof User user) {          // login local
                    username = user.getUsername();
                    fullName = user.getName();
                } else if (principal instanceof OidcUser oidc) {   // Google
                    username = oidc.getEmail();
                    fullName = oidc.getFullName();
                } else {
                    username = "anonymous";
                    fullName = "anonymous";
                }

                List<String> roles = context.getPrincipal().getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();

                context.getClaims()
                        .claim("authorities", roles)
                        .claim("name", fullName)
                        .claim("username", username);
            }
        };
    }


//    private static com.nimbusds.jose.jwk.RSAKey generateRsa() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        return new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
//    }
//
//    private static KeyPair generateRsaKey() {
//        KeyPair keyPair;
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            keyPair = keyPairGenerator.generateKeyPair();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return keyPair;
//    }


}
