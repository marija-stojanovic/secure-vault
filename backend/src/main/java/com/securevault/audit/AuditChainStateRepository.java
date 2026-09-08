package com.securevault.audit;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.util.Optional;

public interface AuditChainStateRepository extends JpaRepository<AuditChainState, Integer> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select state from AuditChainState state where state.id = :id")
    Optional<AuditChainState> findByIdForUpdate(@Param("id") int id);
}
