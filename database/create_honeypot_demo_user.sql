-- Pokrenuti jednom kao MySQL root/administratorski korisnik.
-- Ovaj nalog koristi samo namjerno ranjivi demonstracioni upit.

CREATE USER IF NOT EXISTS 'secure_vault_honeypot_demo'@'localhost'
IDENTIFIED BY 'honey_demo_sigurnost_2026';

-- Ako je nalog postojao, prvo ukloni sva eventualna ranija prava.
REVOKE ALL PRIVILEGES, GRANT OPTION
FROM 'secure_vault_honeypot_demo'@'localhost';

-- Najmanja potrebna privilegija: čitanje samo lažnih tajni.
GRANT SELECT
ON secure_vault.honeytokens
TO 'secure_vault_honeypot_demo'@'localhost';

SHOW GRANTS FOR 'secure_vault_honeypot_demo'@'localhost';
