# Getting Started

Authorization Server METADATA

```bash
curl http://localhost:8080/.well-known/oauth-authorization-server | jq
```

JWKS endpoints
```bash
curl http://localhost:8080/oauth2/jwks | jq
```

Client credentials
```bash
curl -v -X POST http://localhost:8080/oauth2/token \
  -u example-client:bonjour \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=api.read"
```

Authorization endpoint
```bash
curl -v -X POST http://localhost:8080/oauth2/token \
  -u example-client:bonjour \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=1234" \
  -d "scope=api.read"
```


## DOCUMENTACION DE SEGURIDAD
```bash
https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/getting-started.html
```
