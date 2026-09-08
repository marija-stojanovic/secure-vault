package com.securevault.honeypot;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Izvršava isključivo namjerno ranjivi SQL upit demonstracionog honeypot endpointa.
 * Ne koristi glavni Spring DataSource: konekcija se otvara pomoću posebnog MySQL
 * naloga koji smije čitati samo tabelu secure_vault.honeytokens.
 */
@Component
public class IsolatedHoneypotQueryExecutor {

    private final String url;
    private final String username;
    private final String password;

    public IsolatedHoneypotQueryExecutor(
            @Value("${app.honeypot.demo-datasource.url}") String url,
            @Value("${app.honeypot.demo-datasource.username}") String username,
            @Value("${app.honeypot.demo-datasource.password}") String password) {
        this.url = url;
        this.username = username;
        this.password = password;
    }

    public int unsafeSearch(String query) {
        // NAMJERNO RANJIVO radi demonstracije SQL Injection napada.
        // Sigurnosna granica je MySQL nalog sa SELECT pravom samo nad honeytokens.
        String unsafeSql = "SELECT id, decoy_name FROM honeytokens "
                + "WHERE active = TRUE AND decoy_name = '" + query + "' LIMIT 10";

        try (Connection connection = DriverManager.getConnection(url, username, password)) {
            connection.setReadOnly(true);
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery(unsafeSql)) {
                int matches = 0;
                while (result.next()) matches++;
                return matches;
            }
        } catch (SQLException exception) {
            throw new HoneypotQueryException(exception.getErrorCode(), exception);
        }
    }

    public static final class HoneypotQueryException extends RuntimeException {
        private final int databaseErrorCode;

        private HoneypotQueryException(int databaseErrorCode, SQLException cause) {
            super("Izolovani honeypot upit nije izvršen", cause);
            this.databaseErrorCode = databaseErrorCode;
        }

        public int getDatabaseErrorCode() {
            return databaseErrorCode;
        }
    }
}
