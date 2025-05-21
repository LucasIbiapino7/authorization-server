package com.cosmo.auth_server.repositories;

import com.cosmo.auth_server.enitities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByAuthority(String authority);
}
