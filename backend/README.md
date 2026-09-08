# Secure Vault backend

Spring Boot API za Secure Vault. Projekat koristi Java 21, Maven i MySQL 8.

## Lokalno pokretanje

MySQL schema `secure_vault` i korisnik `secure_vault_app` moraju vec postojati.
Lokalna konekcija je podesena u `src/main/resources/application.properties`.

```powershell
mvn spring-boot:run
```

Alternativno se moze koristiti Maven Wrapper:

```powershell
.\mvnw.cmd spring-boot:run
```

Provjera rada:

```text
GET https://localhost:8443/api/health
GET https://localhost:8443/actuator/health
```

Backend direktno slusa samo lokalno na `https://127.0.0.1:8444`, dok se
aplikaciji pristupa kroz HTTPS API Gateway na portu `8443`. Prije prvog
pokretanja instalirati razvojni CA pokretanjem
`certificates\install-dev-ca.ps1` iz korijena projekta.

Ocekivani odgovor aplikacijskog endpointa:

```json
{
  "status": "UP",
  "service": "secure-vault-backend"
}
```

## Testovi

```powershell
mvn test
```

Hibernate koristi `ddl-auto=validate`: pri pokretanju provjerava da postojeca
MySQL sema odgovara JPA entitetima, ali je ne mijenja. Aplikacijski nalog
`secure_vault_app` ima samo `SELECT`, `INSERT`, `UPDATE` i `DELETE` prava.
Promjene strukture, trigeri i pocetni podaci primjenjuju se odvojenim SQL
skriptama koje se izvrsavaju administratorskim MySQL nalogom.
