-- Pokrenuti kao MySQL root/administratorski korisnik nakon gašenja backenda.
USE secure_vault;

-- Hibernate kreira/dopunjava tabele, ali se početni kontrolni red osigurava ručno.
INSERT INTO audit_chain_state (id, last_audit_log_id, last_hash, updated_at)
VALUES (1, NULL, NULL, CURRENT_TIMESTAMP(6))
ON DUPLICATE KEY UPDATE id = id;

-- Aplikacijski Admin nema endpoint za izmjenu ili brisanje audit zapisa.
-- Triggeri dodatno odbijaju UPDATE i DELETE čak i ako se takav SQL pokuša izvršiti.
DROP TRIGGER IF EXISTS trg_audit_logs_no_update;
DROP TRIGGER IF EXISTS trg_audit_logs_no_delete;

DELIMITER $$

CREATE TRIGGER trg_audit_logs_no_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Audit log records are immutable';
END$$

CREATE TRIGGER trg_audit_logs_no_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Audit log records are immutable';
END$$

DELIMITER ;

SHOW TRIGGERS FROM secure_vault WHERE `Table` = 'audit_logs';
