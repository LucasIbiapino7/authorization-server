package com.cosmo.auth_server.services;

import com.cosmo.auth_server.dtos.RegisterDTO;
import com.cosmo.auth_server.enitities.Role;
import com.cosmo.auth_server.enitities.User;
import com.cosmo.auth_server.enums.AuthProvider;
import com.cosmo.auth_server.repositories.RoleRepository;
import com.cosmo.auth_server.repositories.UserRepository;
import com.cosmo.auth_server.services.exceptions.EmailException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    public void register(RegisterDTO dto) {
        if (userRepository.existsByEmail(dto.getEmail().toLowerCase())){
            throw new EmailException("Invalid Email!");
        }
        User newUser = new User();
        newUser.setEmail(dto.getEmail().toLowerCase());
        newUser.setName(dto.getName());
        newUser.setProvider(AuthProvider.LOCAL);
        newUser.setPassword(passwordEncoder.encode(dto.getPassword()));
        Role roleUser = roleRepository.findByAuthority("ROLE_USER");
        newUser.addRole(roleUser);
        userRepository.save(newUser);
    }
}
