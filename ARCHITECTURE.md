# Secure Vault — arhitektura sistema

## 1. Svrha dokumenta

Ovaj dokument opisuje sigurnosnu i tehničku arhitekturu sistema Secure Vault. Sistem omogućava čuvanje i dijeljenje lozinki, API ključeva, sertifikata i drugih tajni, pri čemu backend nikada ne dobija njihov dekriptovani sadržaj.

Glavni princip je **zero-knowledge**: enkripcija i dekripcija korisničkih tajni obavljaju se isključivo u browseru. Server čuva samo šifrate, javne ključeve, šifrovane privatne ključeve i minimalne metapodatke potrebne za rad sistema.

## 2. Izabrane tehnologije

| Dio sistema | Tehnologija |
| --- | --- |
| SPA frontend | React, TypeScript i Vite; Node.js se koristi za razvoj i izgradnju aplikacije |
| API Gateway | Spring Cloud Gateway |
| Backend API | Java 21 i Spring Boot |
| Autentikacija i autorizacija | Spring Security |
| Baza podataka | MySQL 8 |
| Rate limiting i privremene sigurnosne evidencije | Redis |
| Klijentska kriptografija | Standardni Web Crypto API browsera |
| MFA | TOTP kompatibilan sa authenticator aplikacijama |
| OIDC | Spring Security OAuth2/OIDC Client, npr. Google kao provider |
| Pokretanje | Lokalno, bez Dockera |

Struktura repozitorijuma biće:

```text
SecureVault/
├── backend/
├── gateway/
├── frontend/
├── database/
│   ├── secure_vault_schema.sql
│   └── SecureVault.mwb
└── ARCHITECTURE.md
```

Flyway se neće koristiti. Početna šema nalazi se u `database/secure_vault_schema.sql`. Kasnije promjene postojeće baze čuvaće se kao numerisane SQL skripte u `database/updates/`, na primjer `001_add_column.sql`.

## 3. Komponente i granice povjerenja

```text
Korisnikov browser
  ├── React interfejs
  ├── Web Crypto API
  └── dekriptovani podaci postoje samo privremeno u memoriji
             │
             │ HTTPS (lokalno HTTP, port 8080)
             ▼
       API Gateway :8080
  ├── rate limiting
  ├── provjera sumnjivih zahtjeva
  └── blokiranje IP adresa
             │
             ▼
       Spring Boot API 127.0.0.1:8081
  ├── autentikacija i autorizacija
  ├── poslovna pravila
  ├── upravljanje šifratima i omotima ključeva
  └── audit i sigurnosni događaji
        │              │
        ▼              ▼
      MySQL          Redis
```

Browser je jedina komponenta koja smije raspolagati master lozinkom, dešifrovanim privatnim ključem, ključem konkretne tajne i sadržajem tajne u otvorenom obliku.

Frontend ne poziva backend direktno. Pozivi ka `/api/**`, početak OIDC prijave
preko `/oauth2/**` i OIDC callback preko `/login/oauth2/**` prvo dolaze na Gateway.
Gateway ih bez promjene putanje prosljeđuje backendu. CORS pravila nalaze se na
Gatewayu, jer je on jedina javna ulazna tačka. Backend je vezan za loopback adresu
`127.0.0.1` i prihvata proslijeđena HTTP zaglavlja potrebna za ispravne javne URL-ove.

API Gateway i backend smatraju se nepouzdanim u odnosu na sadržaj korisničkih tajni. Kompromitovan server može ukrasti ili izmijeniti šifrate i metapodatke, ali iz baze ne bi smio moći dešifrovati postojeće tajne.

### 3.1. Redis rate limiting na Gatewayu

Gateway prije prosljeđivanja osjetljivih autentikacionih zahtjeva koristi distribuirani
token-bucket brojač u Redis-u. Ključ brojača sastoji se od grupe endpointa i SHA-256
otiska klijentske IP adrese, pa se puna IP adresa ne zapisuje u Redis ključ.

Podrazumijevana ograničenja su:

- 5 pokušaja provjere login lozinke u 60 sekundi;
- 10 MFA pokušaja u 5 minuta;
- 5 registracija ili OIDC postavki u jednom satu.

Dozvoljen zahtjev troši jedan token, a tokeni se postepeno obnavljaju. Kada nema
tokena, Gateway vraća `429 Too Many Requests` i `Retry-After`, bez pozivanja backenda.
Lua skripta u Redis-u čini čitanje, preračunavanje i upis brojača jednom atomskom
operacijom. Ako Redis nije dostupan, zaštićeni auth endpointi vraćaju `503`, dok
ostali endpointi nastavljaju raditi.

Ponavljana prekoračenja predstavljaju sigurnosne prekršaje. Tri prekoračenja u
periodu od 15 minuta automatski blokiraju IP adresu na 30 minuta. Aktivna blokada
čuva se u `blocked_ip_addresses`, a Redis drži njenu brzu privremenu kopiju.
Gateway provjerava blokadu prije prosljeđivanja API zahtjeva i vraća `403 Forbidden`.
Admin može pregledati aktivne blokade i odblokirati adresu; recovery endpoint je
dostupan kroz Gateway, ali ga backend i dalje štiti obaveznom ADMIN autorizacijom.

## 4. Podaci koje server vidi

Server smije vidjeti:

- korisničko ime, email, ulogu i status naloga;
- hash login lozinke;
- javni ključ korisnika;
- KDF salt i javne KDF parametre;
- šifrovani privatni ključ;
- šifrovane sadržaje tajni i njihove inicijalizacione vektore;
- ključeve tajni omotane javnim ključevima primalaca;
- članstvo u timu, vrijeme aktivnosti, IP adresu i audit metapodatke.

Server ne smije dobiti:

- master lozinku;
- ključ izveden iz master lozinke;
- privatni asimetrični ključ u otvorenom obliku;
- neomotani AES ključ tajne;
- naziv, vrijednost ili druge osjetljive podatke tajne u otvorenom obliku.

Naziv i sadržaj tajne zajedno se serijalizuju i šifruju u jedan `encrypted_blob`. Zbog toga server ne može pretraživati tajne po njihovom stvarnom nazivu.

## 5. Lozinke korisnika

Koriste se dvije različite lozinke:

### 5.1. Login lozinka

Login lozinka služi za autentikaciju prema backendu. Šalje se isključivo kroz HTTPS. Backend je obrađuje standardnim `PasswordEncoder` mehanizmom, a u tabeli `users` čuva samo njen Argon2id hash.

### 5.2. Master lozinka

Master lozinka služi samo za otključavanje kriptografskog materijala u browseru. Ne šalje se backendu, ne upisuje se u bazu, kolačić, `localStorage`, log ili analitiku.

Iz master lozinke browser izvodi 256-bitni ključ pomoću PBKDF2-HMAC-SHA-256, slučajnog salt-a i konfigurabilnog broja iteracija. Salt i broj iteracija nisu tajni i čuvaju se u tabeli `user_crypto_material`.

Promjena login lozinke i promjena master lozinke dvije su odvojene operacije. Pri promjeni master lozinke ponovo se šifruje samo privatni ključ korisnika, a ne sve njegove tajne.

## 6. Kriptografski algoritmi i pravila

Koriste se isključivo standardne implementacije iz Web Crypto API-ja i provjerenih Java biblioteka. Neće se pisati vlastita implementacija kriptografskih algoritama.

| Namjena | Algoritam |
| --- | --- |
| Izvođenje ključa iz master lozinke | PBKDF2-HMAC-SHA-256 sa slučajnim salt-om |
| Šifrovanje privatnog ključa | AES-256-GCM |
| Šifrovanje sadržaja tajne | AES-256-GCM |
| Asimetrični par korisnika | RSA-OAEP, 3072 bita, SHA-256 |
| Omotavanje ključa tajne | RSA-OAEP sa javnim ključem primaoca |
| Hash audit lanca i tokena | SHA-256 |
| Login lozinka | Argon2id kroz Spring Security |

Za svaku AES-GCM operaciju generiše se nov, kriptografski slučajan IV. Isti par ključa i IV-a nikada se ne smije ponovo koristiti. Web Crypto AES-GCM rezultat sadrži autentikacioni tag zajedno sa šifratom.

Privatni ključ se u browseru drži samo dok je vault otključan. Ne čuva se dekriptovan u `localStorage`, `sessionStorage`, IndexedDB niti na serveru. Zaključavanje vaulta, odjava ili istek sesije uklanjaju reference na dekriptovani ključ iz stanja aplikacije.

## 7. Registracija korisnika

Registracija se izvršava ovim redoslijedom:

1. Korisnik unosi korisničko ime, email, login lozinku i master lozinku.
2. Frontend provjerava da master lozinka zadovoljava politiku minimalne dužine.
3. Browser generiše RSA-OAEP par ključeva.
4. Browser generiše slučajni KDF salt.
5. PBKDF2 iz master lozinke izvodi AES-256 ključ.
6. Privatni RSA ključ izvozi se u PKCS#8 obliku i šifruje pomoću AES-256-GCM.
7. Frontend šalje login podatke, javni ključ, salt, KDF parametre, IV i šifrovani privatni ključ.
8. Backend hashira login lozinku i upisuje korisnika u `users`.
9. Kriptografski materijal upisuje se u `user_crypto_material`.
10. Korisnik konfiguriše TOTP i potvrđuje prvi kod prije aktivacije naloga.

Ako korisnik izgubi master lozinku, server ne može vratiti privatni ključ niti dešifrovati tajne. To je očekivana posljedica zero-knowledge dizajna i mora biti jasno prikazana korisniku.

## 8. Prijava i otključavanje vaulta

1. Korisnik šalje korisničko ime i login lozinku kroz HTTPS.
2. Nakon uspješne prve provjere backend traži TOTP kod.
3. Backend provjerava TOTP i kreira sesiju.
4. Session/access i refresh vrijednosti šalju se u kolačićima sa `HttpOnly`, `Secure` i `SameSite=Strict` atributima.
5. Frontend preuzima salt, KDF parametre i šifrovani privatni ključ.
6. Korisnik lokalno unosi master lozinku.
7. Browser izvodi AES ključ i pokušava AES-GCM dekripciju privatnog ključa.
8. Uspješna dekripcija otključava vault samo u trenutnoj memoriji browsera.

Backend ne može potvrditi tačnost master lozinke jer je ne prima. Neuspješna AES-GCM provjera lokalno znači da je master lozinka pogrešna ili da je šifrat izmijenjen.

## 9. Kreiranje i čitanje tajne

### Kreiranje

1. Browser generiše novi slučajni 256-bitni AES data encryption key — DEK.
2. Naziv, tip i vrijednost tajne pretvaraju se u kanonski JSON.
3. JSON se šifruje pomoću AES-256-GCM i novog IV-a.
4. DEK se omotava javnim RSA ključem vlasnika.
5. Backend dobija samo šifrat, IV, algoritme i omotani DEK.
6. Metapodaci se upisuju u `secrets`, šifrat u `secret_versions`, a omotani ključ u `secret_key_envelopes`.

### Čitanje

1. Backend autorizuje korisnika i vraća šifrat posljednje verzije i njegov omotani DEK.
2. Browser privatnim RSA ključem odmotava DEK.
3. Browser pomoću DEK-a i IV-a dešifruje sadržaj.
4. Otvoreni sadržaj prikazuje se samo u interfejsu i ne vraća serveru.

### Ažuriranje i brisanje

Ažuriranje kreira novi red u `secret_versions`. Ne mijenja se stari šifrat. Za novu verziju kreiraju se novi IV i novi DEK, te novi omoti ključa za sve aktivne primaoce.

Brisanje je prvo logičko postavljanjem `secrets.deleted_at`. Trajno uklanjanje šifrata može biti naknadni kontrolisani proces, ali zapis o događaju ostaje u audit lancu.

## 10. Sigurno dijeljenje

Team Lead smije dijeliti timsku tajnu samo aktivnom Developeru koji je član odgovarajućeg tima.

1. Frontend Team Leada preuzima javni ključ Developera sa servera.
2. Browser provjerava identifikator/fingerprint preuzetog javnog ključa.
3. Privatni ključ Team Leada odmotava DEK tajne.
4. Isti DEK omotava se javnim ključem Developera.
5. Novi omotani DEK šalje se backendu i upisuje u `secret_key_envelopes`.
6. Developer svojim privatnim ključem kasnije odmotava DEK i dešifruje šifrat.

Sadržaj tajne ne mora se ponovo šifrovati za svakog korisnika. Svaki primalac dobija samo zaseban omot istog DEK-a. Prilikom rotacije tajne pravi se nova verzija sa novim DEK-om.

Ukidanje pristupa označava omot kao opozvan postavljanjem `revoked_at`. To sprečava buduće preuzimanje, ali ne može učiniti da korisnik zaboravi podatak koji je ranije već dešifrovao. Ovo je inherentno ograničenje svakog sistema dijeljenja tajni.

## 11. Uloge i autorizacija

### Admin

- upravlja korisničkim nalozima i njihovim statusom;
- definiše sigurnosne politike;
- pregleda sigurnosna upozorenja i audit događaje;
- zamrzava i odmrzava naloge;
- ne može dešifrovati korisničke tajne samo zato što je Admin.

### Team Lead

- upravlja članovima svog tima;
- kreira i upravlja timskim tajnama;
- dijeli tajne Developerima iz svog tima;
- opoziva pristup dijeljenim tajnama.

### Developer

- vidi i dešifruje samo tajne za koje postoji aktivan omot ključa namijenjen njemu;
- može upravljati vlastitim tajnama;
- ne može dijeliti timske tajne niti mijenjati sigurnosne politike.

Backend provjerava autorizaciju pri svakom zahtjevu. Sakrivanje dugmeta u frontend interfejsu nije sigurnosna kontrola.

## 12. MFA i OIDC

TOTP je obavezan za sve uloge. TOTP seed se mora privremeno prikazati korisniku kao QR kod tokom aktivacije. Backend mora imati mogućnost provjere TOTP koda, pa se seed čuva u `user_mfa` šifrovan AES-GCM aplikacionim ključem koji se nalazi izvan baze, kroz environment varijablu.

Ponovna upotreba TOTP koda u istom vremenskom koraku sprečava se poljem `last_used_time_step`.

OIDC omogućava prijavu eksternim nalogom. Veza između lokalnog korisnika i OIDC identiteta čuva se u `oidc_identities`. OIDC zamjenjuje prvi faktor prijave, ali ne ukida obavezni aplikacioni TOTP niti potrebu za master lozinkom radi lokalnog otključavanja vaulta.

## 13. Sesije i zaštita kolačića

- Access token/sesija kratko traje; početna vrijednost je 15 minuta i Admin je može konfigurisati.
- Refresh token je slučajna vrijednost, a baza čuva samo njen SHA-256 hash.
- Refresh token se rotira pri svakoj upotrebi.
- Ponovna upotreba starog refresh tokena opoziva cijelu porodicu tokena (`token_family_id`).
- Kolačići koriste `HttpOnly`, `Secure`, `SameSite=Strict` i ograničenu putanju.
- Produkcijski saobraćaj dozvoljen je samo preko HTTPS-a.
- Za zahtjeve koji mijenjaju stanje koristi se dodatna CSRF zaštita.
- Odjava opoziva serversku sesiju i zaključava vault u browseru.

## 14. API Gateway i rate limiting

Sav spoljašnji API saobraćaj prvo prolazi kroz Gateway. Backend API u produkcijskoj konfiguraciji nije direktno izložen korisniku.

Redis čuva kratkotrajne brojače po IP adresi i korisničkom identifikatoru. Najstrožija ograničenja važe za login, TOTP, refresh i OIDC callback rute. Gateway i backend bilježe:

- veliki broj neuspješnih login ili TOTP pokušaja;
- pokušaje korištenja isteklih ili opozvanih tokena;
- neuobičajeno veliki broj zahtjeva za različite tajne;
- obrasce unosa slične SQL injection i XSS napadima;
- pristup honeytoken zapisima.

IP blokade dužeg trajanja čuvaju se u `blocked_ip_addresses`, a detalji pokušaja u `authentication_attempts`.

Pošto se stvarna dekripcija odvija lokalno, server ne može pouzdano znati svaki neuspješan pokušaj master dekripcije. Frontend može prijaviti takav događaj tokom legitimne sesije, ali napadač može izmijeniti klijentski kod i izostaviti prijavu. Ova granica mora biti navedena u dokumentaciji i na odbrani.

## 15. Honeytoken sistem

Lažni zapisi čuvaju se u posebnoj tabeli `honeytokens` i regularni secrets servis ih nikada ne vraća. Pristup honeytokenu proizvodi kritični sigurnosni događaj:

1. aktivni korisnički nalog prelazi u status `FROZEN`;
2. sve njegove sesije se opozivaju;
3. IP adresa se privremeno blokira;
4. kreira se `security_alerts` zapis;
5. Admin dobija obavještenje;
6. događaj se dodaje u audit lanac.

Namjerno ranjiv SQL injection endpoint postoji isključivo za demonstraciju. Biće dostupan samo u posebnom Spring profilu `vulnerable-demo`, samo na lokalnom računaru, uz dodatnu privremenu administratorsku aktivaciju i automatsko gašenje. Ne smije postojati u produkcijskom profilu niti koristiti produkcijske podatke.

## 16. Nepromjenjivi audit log

Svaka osjetljiva radnja pravi `audit_logs` zapis: login, neuspješan MFA, pristup tajni, kreiranje verzije, dijeljenje, opoziv pristupa, promjena politike, zamrzavanje naloga i honeytoken događaj.

Hash se računa nad prethodnim hashom i kanonskim sadržajem cijelog novog događaja:

```text
entry_hash = SHA-256(previous_hash || canonical_event_data)
```

Backend u jednoj transakciji zaključava red `audit_chain_state`, upisuje novi log i ažurira vrh lanca. Trigeri u MySQL-u zabranjuju `UPDATE` i `DELETE` nad `audit_logs` tabelom.

Admin aplikacije nema funkciju brisanja audit zapisa. MySQL root korisnik tehnički može ukloniti trigere ili promijeniti bazu, pa se za jaču dokazivost vrh hash lanca periodično izvozi ili digitalno potpisuje izvan baze. To ograničenje mora biti iskreno navedeno; sam hash lanac otkriva izmjene samo kada postoji pouzdana kopija očekivanog vrha lanca.

## 17. Model baze podataka

Postojeće tabele grupisane su ovako:

| Oblast | Tabele |
| --- | --- |
| Korisnici i politike | `users`, `security_policies`, `user_crypto_material` |
| Organizacija | `teams`, `team_memberships` |
| Vault i dijeljenje | `secrets`, `secret_versions`, `secret_key_envelopes` |
| Prijava | `user_mfa`, `oidc_identities`, `sessions`, `authentication_attempts` |
| Detekcija napada | `blocked_ip_addresses`, `honeytokens`, `security_alerts` |
| Integritet događaja | `audit_logs`, `audit_chain_state` |

MySQL šema i EER model nalaze se u `database` direktorijumu. Hibernate koristi `spring.jpa.hibernate.ddl-auto=validate`, pa pri pokretanju provjerava usklađenost šeme sa JPA entitetima, ali je ne mijenja. Aplikacijski nalog `secure_vault_app` ograničen je na `SELECT`, `INSERT`, `UPDATE` i `DELETE`. DDL promjene, trigeri, početni podaci i ostali posebni MySQL objekti održavaju se odvojenim SQL skriptama koje izvršava administratorski MySQL nalog.

## 18. Početni API moduli

Backend će biti podijeljen na funkcionalne module:

- `auth` — registracija, login, MFA, OIDC i sesije;
- `user` — profili, statusi i javni ključevi;
- `team` — timovi i članstva;
- `vault` — šifrati, verzije i omoti ključeva;
- `policy` — sigurnosne politike;
- `audit` — formiranje i provjera hash lanca;
- `security` — rate limiting događaji, blokade, honeytokeni i upozorenja.

API nikada ne prihvata polje koje predstavlja dekriptovani sadržaj tajne ili master lozinku.

## 19. Početne sigurnosne pretpostavke

- Korisnikov browser i operativni sistem nisu već kompromitovani.
- Aplikacija se isporučuje preko HTTPS-a bez izmijenjenog JavaScript koda.
- XSS predstavlja kritičan rizik jer izvršeni JavaScript može čitati dekriptovane podatke iz memorije; zato su obavezni stroga Content Security Policy pravila, izbjegavanje `dangerouslySetInnerHTML` i validacija izlaza.
- Server može uskratiti pristup ili obrisati podatke; zero-knowledge štiti povjerljivost, ali sam ne garantuje dostupnost.
- Server može zamijeniti javni ključ korisnika i pokušati MITM pri dijeljenju; zato frontend prikazuje i provjerava fingerprint ključa, a promjena javnog ključa mora proizvesti audit i upozorenje.
- HTTPS, ograničene CORS postavke, validacija zahtjeva i parametrizovani SQL/JPA upiti obavezni su u svim normalnim profilima.

## 20. Redoslijed implementacije

1. Kreirati Spring Boot backend i povezati ga sa postojećom MySQL bazom.
2. Mapirati `users`, `security_policies` i `user_crypto_material` entitete.
3. Implementirati registraciju bez master lozinke na backend zahtjevu.
4. Kreirati React frontend i Web Crypto servis za generisanje ključeva.
5. Implementirati login, TOTP i sigurnu sesiju.
6. Implementirati CRUD šifrovanih tajni i njihove verzije.
7. Implementirati timove i dijeljenje omotanog DEK-a.
8. Dodati OIDC prijavu.
9. Dodati Gateway, Redis rate limiting i IP detekciju/blokiranje (implementirano); zatim proširiti detekciju sadržaja sumnjivih zahtjeva.
10. Implementirati audit lanac, honeytokene i kontrolisani demonstracioni endpoint.
11. Izvršiti funkcionalne, integracione i sigurnosne testove.
