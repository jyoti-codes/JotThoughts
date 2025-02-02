package com.secure.notes.repositories;

import com.secure.notes.models.AuditLog;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

	List<AuditLog> findByNoteId(Long noteId);
}