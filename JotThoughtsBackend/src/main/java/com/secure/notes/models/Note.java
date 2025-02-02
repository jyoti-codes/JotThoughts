package com.secure.notes.models;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import lombok.Data;

@Entity
//@Data
public class Note {
	
		@Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private Long id;

	   // @Lob
	    private String content;

	    private String ownerUsername;

		public Long getId() {
			return id;
		}

		public void setId(Long id) {
			this.id = id;
		}

		public String getContent() {
			return content;
		}

		public void setContent(String content) {
			this.content = content;
		}

		public String getOwnerUsername() {
			return ownerUsername;
		}

		public void setOwnerUsername(String ownerUsername) {
			this.ownerUsername = ownerUsername;
		}

	    
}
