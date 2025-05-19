INSERT INTO tb_user (name, email, password) VALUES ('Maria Brown', 'maria@gmail.com', '$2a$10$eAkzygNpH0RYyItpK3W55eqRwLywXaFO2AhPnp7FKwd7xODd.zS0e');
INSERT INTO tb_user (name, email, password) VALUES ('Alex Green', 'lucas@gmail.com', '$2a$10$eAkzygNpH0RYyItpK3W55eqRwLywXaFO2AhPnp7FKwd7xODd.zS0e');

INSERT INTO tb_role (authority) VALUES ('ROLE_USER')
INSERT INTO tb_role (authority) VALUES ('ROLE_ADMIN')

INSERT INTO tb_user_role(user_id, role_id) VALUES (1,1)
INSERT INTO tb_user_role(user_id, role_id) VALUES (2,1)
INSERT INTO tb_user_role(user_id, role_id) VALUES (2,2)