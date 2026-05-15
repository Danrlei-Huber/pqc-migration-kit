package com.pqc.hybrid.rfc;

import java.time.LocalDate;
import java.util.List;

/**
 * Service interface for monitoring the status of IETF drafts relevant to the PQC Hybrid Library.
 * 
 * This service provides functionality to check the status, expiration, and changes of IETF drafts
 * that the library tracks for compliance and standardization purposes.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public interface IETFDraftMonitor {

    /**
     * Checks the current status of a specified IETF draft.
     * 
     * @param draftIdentifier The identifier of the IETF draft (e.g., "draft-ietf-lamps-pq-composite-sigs")
     * @return An RFCStatus object containing the current status information
     * @throws RFCMonitoringException if there is an error retrieving the draft status
     */
    RFCStatus checkDraftStatus(String draftIdentifier) throws RFCMonitoringException;

    /**
     * Checks if the specified IETF draft is expiring soon.
     * 
     * @param draftIdentifier The identifier of the IETF draft
     * @param daysThreshold   The number of days before expiration to consider "expiring soon"
     * @return true if the draft is expiring within the threshold, false otherwise
     * @throws RFCMonitoringException if there is an error checking the draft status
     */
    boolean isExpiringSoon(String draftIdentifier, int daysThreshold) throws RFCMonitoringException;

    /**
     * Gets a list of all drafts currently being monitored by the library.
     * 
     * @return List of draft identifiers being monitored
     */
    List<String> getMonitoredDrafts();

    /**
     * Registers a new draft for monitoring.
     * 
     * @param draftIdentifier The identifier of the draft to monitor
     * @param draftUrl        The URL where the draft can be accessed (optional)
     */
    void registerDraft(String draftIdentifier, String draftUrl);
}