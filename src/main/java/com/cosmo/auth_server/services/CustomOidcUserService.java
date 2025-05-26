package com.cosmo.auth_server.services;

import com.cosmo.auth_server.enitities.Role;
import com.cosmo.auth_server.enitities.User;
import com.cosmo.auth_server.enums.AuthProvider;
import com.cosmo.auth_server.repositories.RoleRepository;
import com.cosmo.auth_server.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;

@Component
@Transactional
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // Busca os dados do google
        OidcUser oidcUser = new OidcUserService().loadUser(userRequest);
        String email = oidcUser.getEmail();
        String name  = oidcUser.getFullName();

        // Verificando se o usuário já existe no banco de dados
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            Role defaultRole = roleRepository.findByAuthority("ROLE_USER");
            User newUser = new User();
            newUser.setName(name);
            newUser.setEmail(email);
            newUser.setPassword(null);
            newUser.setProvider(AuthProvider.GOOGLE);
            newUser.addRole(defaultRole);
            return userRepository.save(newUser);
        });

        List<SimpleGrantedAuthority> authorities =
                user.getRoles().stream()
                        .map(r -> new SimpleGrantedAuthority(r.getAuthority()))
                        .toList();

        return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo(), "email") {
            @Override public String getName() { return user.getEmail(); }
        };
    }
}
