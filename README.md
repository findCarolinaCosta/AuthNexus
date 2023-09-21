# Servidor OAuth2 Spring

Este projeto é um servidor OAuth2 construído com o Spring Framework. O servidor OAuth2 permite que
você implemente autenticação e autorização seguras em sua aplicação, permitindo que terceiros
acessem recursos protegidos em nome dos clientes cadastrados.

## Pré-requisitos

Certifique-se de ter as seguintes ferramentas e recursos instalados antes de começar:

- Java Development Kit (JDK) - Java 17
- Spring Boot
- Uma IDE de sua escolha (por exemplo, IntelliJ IDEA, Eclipse)
- Git

## Configurations

1. Clone this repository:

   ```bash
   git clone https://github.com/findCarolinaCosta/AuthNexus.git
   ```

# Import the project into IDE.

Configure the application properties in the application.properties or application.yml file to
match your specific needs, including database configuration and OAuth2 credentials.

Note: application-example.properties with example properties.

# Execute the Spring Boot server:

```bash
 mvn spring-boot:run
```

The OAuth2 server will be running at http://localhost:8080 (default). Be sure to adjust the
port settings, if necessary.

# Recurses

1. Authorization Route (**/oauth2/authorize**):
    - This endpoint is used to initiate the authorization process.
    - It is accessed via a GET request, and the user is redirected to this route to authorize the
      client application.

2. Code Exchange Route for Token (**/oauth2/token**):
    - This endpoint is used to exchange an authorization code for an access token.
    - It is accessed via a POST request, usually with client credentials (client ID and secret) and
      the authorization code as parameters.

3. Token Refresh Route (**/oauth2/token**):
    - This endpoint is used to request a new access token using a refresh token.
    - It is accessed via a POST request with the refresh token as body parameter.

4. Token Revocation Route (**/oauth2/revoke**
    - This route is used to revoke tokens, ending user sessions or revoking access permissions.
    - It can be accessed via POST request send the token to be revoked as body parameter.

5. Token Introspection Route (**/oauth2/introspect**):
    - This endpoint is used to verify the validity of an access token.
    - It can be accessed via POST request, with the access token to be verified as body parameter.

# Documentation

Incluse in the project json file for insomnia tests.

# License

The MIT License (MIT)

# Author

[Carolina P C](www.linkedin.com/in/carolinapereiradev)
