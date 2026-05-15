package com.pqc.hybrid.rfc;

import java.time.LocalDate;
import java.util.List;

/**
 * Data class representing the status of an IETF draft.
 * 
 * This class holds all the relevant information about an IETF draft's current status,
 * including expiration date, authors, and abstract.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class RFCStatus {

    /** The identifier of the draft (e.g., "draft-ietf-lamps-pq-composite-sigs-18") */
    private String draftIdentifier;

    /** The title of the draft */
    private String title;

    /** The current status of the draft (e.g., "Active", "Expired", "Proposed Standard") */
    private String status;

    /** The expiration date of the draft */
    private LocalDate expiresDate;

    /** The stream the draft belongs to (e.g., "IETF", "IRTF") */
    private String stream;

    /** The list of authors */
    private List<String> authors;

    /** The abstract of the draft */
    private String abstractText;

    /** The URL where the draft can be accessed */
    private String documentUrl;

    /**
     * Constructs a new RFCStatus with the specified values.
     * 
     * @param draftIdentifier The identifier of the draft
     * @param title The title of the draft
     * @param status The current status of the draft
     * @param expiresDate The expiration date of the draft
     * @param stream The stream the draft belongs to
     * @param authors The list of authors
     * @param abstractText The abstract of the draft
     * @param documentUrl The URL where the draft can be accessed
     */
    public RFCStatus(String draftIdentifier, String title, String status, LocalDate expiresDate, String stream, List<String> authors, String abstractText, String documentUrl) {
        this.draftIdentifier = draftIdentifier;
        this.title = title;
        this.status = status;
        this.expiresDate = expiresDate;
        this.stream = stream;
        this.authors = authors;
        this.abstractText = abstractText;
        this.documentUrl = documentUrl;
    }

    // Getters and Setters
    public String getDraftIdentifier() {
        return draftIdentifier;
    }

    public void setDraftIdentifier(String draftIdentifier) {
        this.draftIdentifier = draftIdentifier;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDate getExpiresDate() {
        return expiresDate;
    }

    public void setExpiresDate(LocalDate expiresDate) {
        this.expiresDate = expiresDate;
    }

    public String getStream() {
        return stream;
    }

    public void setStream(String stream) {
        this.stream = stream;
    }

    public List<String> getAuthors() {
        return authors;
    }

    public void setAuthors(List<String> authors) {
        this.authors = authors;
    }

    public String getAbstract() {
        return abstractText;
    }

    public void setAbstract(String abstractText) {
        this.abstractText = abstractText;
    }

    public String getDocumentUrl() {
        return documentUrl;
    }

    public void setDocumentUrl(String documentUrl) {
        this.documentUrl = documentUrl;
    }

    @Override
    public String toString() {
        return "RFCStatus{" +
                "draftIdentifier='" + draftIdentifier + '\'' +
                ", title='" + title + '\'' +
                ", status='" + status + '\'' +
                ", expiresDate=" + expiresDate +
                ", stream='" + stream + '\'' +
                ", authorsCount=" + (authors != null ? authors.size() : 0) +
                ", documentUrl='" + documentUrl + '\'' +
                '}';
    }
}