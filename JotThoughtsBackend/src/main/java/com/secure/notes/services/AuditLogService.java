package com.secure.notes.services;

import java.util.List;

import com.secure.notes.models.AuditLog;
import com.secure.notes.models.Note;

public interface AuditLogService {
    void logNoteCreation(String username, Note note);

    void logNoteUpdate(String username, Note note);

    void logNoteDeletion(String username, Long noteId);

	List<AuditLog> getAllAuditLogs();

	List<AuditLog> getAuditLogsForNoteId(Long id);
}