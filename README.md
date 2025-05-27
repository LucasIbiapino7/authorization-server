# 🔐 Authorization Server com Login via Google

Este projeto é um Authorization Server moderno, desenvolvido com **Spring Boot**, que implementa autenticação baseada em **OAuth2 + OIDC**, 
incluindo suporte ao fluxo **Authorization Code com PKCE** e **login via Google**. Ideal para aplicações SPA que consomem tokens JWT para autenticação moderna.

##  Funcionalidades

-  Suporte ao fluxo OAuth2 Authorization Code + PKCE
-  Emissão de Access Token (JWT) e ID Token
-  Registro e login local com persistência em banco de dados
-  Login com conta Google (OAuth2 Client)
-  Criação automática de usuários com `provider=GOOGLE` ao autenticar
-  Inclusão de roles (ex.: `ROLE_USER`) no JWT
-  Integração com SPA via OIDC (usando `oidc-client-ts`)
-  Suporte a múltiplos Registered Clients

##  Tecnologias Utilizadas

- **Java**
- **Spring Boot**
- **Spring Authorization Server**
- **Spring Security**
- **Spring Data JPA**
- **PostgreSQL**
- **Flyway**
- **OAuth2 Client (Login com Google)**
- **OIDC (OpenID Connect)**
- **JWT (Json Web Tokens)**
- **oidc-client-ts** (na SPA que consome o Authorization Server)

## 🔄 Fluxo de Autenticação

O Authorization Server suporta dois modos principais de autenticação:

### 1.  Login local (usuário/senha)
1. O usuário acessa a página de login customizada.
2. Insere suas credenciais (e-mail e senha).
3. Se as credenciais forem válidas, um `Authorization Code` é gerado.
4. O cliente troca esse código por um `Access Token` e um `ID Token`.
5. O token contém informações como e-mail e roles do usuário.

### 2.  Login com Google
1. O usuário clica em **"Entrar com Google"** na tela de login.
2. É redirecionado para a tela de consentimento do Google.
3. Após autorização, o Google retorna um token de acesso com dados do usuário.
4. O sistema verifica se o e-mail já existe:
   -  Se sim: autentica normalmente.
   -  Se não: cria um novo usuário com `provider = GOOGLE`.
5. O Authorization Server gera `Access Token` e `ID Token` com os dados do usuário autenticado.

> Em ambos os fluxos, o token é um JWT assinado, contendo claims como `username`, `roles`, `sub`, entre outros.

##  Instalação e Execução

Este projeto **não utiliza `docker-compose`** porque exige a configuração de credenciais do Google OAuth. Por isso, a execução é feita manualmente.

### Pré-requisitos

- Java 17+
- Maven 3.8+
- PostgreSQL rodando localmente ou um container.
- Uma conta no Google Cloud com OAuth 2.0 Client configurado

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/authorization-server.git
cd authorization-server
```

### 2. Você deve criar (ou editar) o arquivo src/main/resources/application.properties com as seguintes variáveis:

#### Configuração do Google OAuth2
```bash
spring.security.oauth2.client.registration.google.client-id=SEU_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=SEU_CLIENT_SECRET
spring.security.oauth2.client.registration.google.redirect-uri=http://localhost:9000/login/oauth2/code/google
```

#### Configuração do banco de dados PostgreSQL
```bash
spring.datasource.url=jdbc:postgresql://localhost:5432/seu_banco
spring.datasource.username=seu_usuario
spring.datasource.password=sua_senha
```

### 3. Execute o projeto
```bash
./mvnw spring-boot:run
```
Ou então na IDE de sua preferência.

A aplicação estará acessível em: http://localhost:9000

## Integração com o Frontend

Este Authorization Server foi desenvolvido para funcionar perfeitamente com uma SPA (Single Page Application) em React, utilizando a biblioteca `oidc-client-ts` para realizar o fluxo Authorization Code + PKCE.

###  Repositório do Frontend

Você pode encontrar o projeto frontend que consome este Authorization Server neste repositório:

👉 [https://github.com/LucasIbiapino7/react-login-interface](https://github.com/LucasIbiapino7/react-login-interface)

###  Como integrar os dois projetos

1. **Certifique-se de que o Authorization Server está rodando em `http://localhost:9000`**
   - É nele que o frontend irá buscar a configuração OIDC.

2. **Clone e instale o frontend**
   - Mais informações no repositório do frontend.

##  Considerações Finais

Este projeto foi desenvolvido como parte do meu portfólio para demonstrar conhecimentos em:

- Spring Authorization Server
- Segurança com OAuth2 e OIDC
- Integração com provedores externos como Google
- Validação e persistência de usuários OAuth
- Emissão de JWT com claims personalizados

Caso tenha interesse em colaborar, sugerir melhorias ou utilizar este projeto como base para estudos, fique à vontade para abrir issues ou forks.

Obrigado por visitar este repositório!

## Licença

Este projeto está sob a licença MIT.


   
