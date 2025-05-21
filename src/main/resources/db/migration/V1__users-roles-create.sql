-- Tabela de roles
CREATE TABLE tb_role (
    id SERIAL PRIMARY KEY,
    authority VARCHAR(100) NOT NULL
);

-- Tabela de usuários
CREATE TABLE tb_user (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

-- Tabela de associação entre usuários e roles
CREATE TABLE tb_user_role (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES tb_user (id),
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES tb_role (id)
);

-- Inserindo usuários
INSERT INTO tb_user (name, email, password)
VALUES
  ('Maria', 'maria@gmail.com', '$2a$10$eAkzygNpH0RYyItpK3W55eqRwLywXaFO2AhPnp7FKwd7xODd.zS0e'),
  ('Lucas', 'lucas@gmail.com', '$2a$10$eAkzygNpH0RYyItpK3W55eqRwLywXaFO2AhPnp7FKwd7xODd.zS0e');

-- Inserindo roles
INSERT INTO tb_role (authority)
VALUES
  ('ROLE_USER'),
  ('ROLE_ADMIN');

-- Associando usuários às roles
INSERT INTO tb_user_role (user_id, role_id) VALUES (1, 1);
INSERT INTO tb_user_role (user_id, role_id) VALUES (2, 1);
INSERT INTO tb_user_role (user_id, role_id) VALUES (2, 2);
