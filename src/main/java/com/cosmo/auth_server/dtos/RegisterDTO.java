package com.cosmo.auth_server.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegisterDTO {

    @NotBlank(message = "campo requerido!")
    @Size(max = 50, min = 2, message = "O nome precisa ter entre 2 e 50 caracteres!")
    private String name;

    @Email(message = "E-mail inválido")
    @NotBlank(message = "campo requerido!")
    private String email;

    @NotBlank(message = "campo requerido!")
    @Size(min = 8, max = 30, message = "A senha deve ter entre 8 e 30 caracteres.")
    private String password;

    public RegisterDTO() {
    }

    public RegisterDTO(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
