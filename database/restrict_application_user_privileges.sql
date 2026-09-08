-- Pokrenuti jednom kao MySQL root/administratorski korisnik.
-- Aplikacijski nalog nakon ove skripte moze samo citati i mijenjati podatke.

CREATE USER IF NOT EXISTS 'secure_vault_app'@'localhost'
IDENTIFIED BY 'sigurnost';

-- secure_vault_app je namjenski nalog samo za ovu aplikaciju, zato uklanjamo
-- sva ranije dodijeljena prava prije dodjele minimalnog skupa.
REVOKE ALL PRIVILEGES, GRANT OPTION
FROM 'secure_vault_app'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE
ON secure_vault.*
TO 'secure_vault_app'@'localhost';

SHOW GRANTS FOR 'secure_vault_app'@'localhost';

