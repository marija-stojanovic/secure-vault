package com.securevault.auth.oidc;

import com.securevault.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

@Entity
@Table(
        name = "oidc_identities",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_oidc_identity",
                columnNames = {"issuer", "subject_identifier"}
        )
)
public class OidcIdentity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "issuer", nullable = false, length = 500)
    private String issuer;

    @Column(name = "subject_identifier", nullable = false, length = 255)
    private String subjectIdentifier;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected OidcIdentity() {
    }

    public OidcIdentity(User user, String issuer, String subjectIdentifier) {
        this.user = user;
        this.issuer = issuer;
        this.subjectIdentifier = subjectIdentifier;
    }

    public User getUser() {
        return user;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubjectIdentifier() {
        return subjectIdentifier;
    }
}
