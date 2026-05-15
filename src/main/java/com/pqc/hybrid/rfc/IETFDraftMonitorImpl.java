package com.pqc.hybrid.rfc;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * Default implementation of the IETFDraftMonitor interface.
 * 
 * This implementation provides mock data for testing and development purposes.
 * In a production environment, this would be replaced with an implementation
 * that queries the IETF Datatracker API.
 * 
 * @author PQC Hybrid Team
 * @version 1.0.0-BETA
 */
public class IETFDraftMonitorImpl implements IETFDraftMonitor {

    /** List of draft identifiers being monitored */
    private final List<String> monitoredDrafts;

    /**
     * Constructs a new IETFDraftMonitorImpl with a default set of monitored drafts.
     */
    public IETFDraftMonitorImpl() {
        this.monitoredDrafts = new ArrayList<>();
        // Add the main draft we are tracking
        this.monitoredDrafts.add("draft-ietf-lamps-pq-composite-sigs");
        // Add a few others for demonstration
        this.monitoredDrafts.add("draft-ietf-lamps-pq-keys");
        this.monitoredDrafts.add("draft-ietf-lamps-cmp-update");
    }

    @Override
    public RFCStatus checkDraftStatus(String draftIdentifier) throws RFCMonitoringException {
        // In a real implementation, we would make an HTTP request to the IETF Datatracker API.
        // For now, we return mock data based on the draft identifier.
        
        if (draftIdentifier == null || draftIdentifier.isEmpty()) {
            throw new RFCMonitoringException("Draft identifier cannot be null or empty", "INVALID_DRAFT_IDENTIFIER");
        }

        // Mock data for the main draft
        if ("draft-ietf-lamps-pq-composite-sigs".equals(draftIdentifier)) {
            return new RFCStatus(
                    "draft-ietf-lamps-pq-composite-sigs-18",
                    "Composite Public Key Algorithms in ML-DSA Signature Context",
                    "Active",
                    LocalDate.of(2026, 10, 11), // Expires October 11, 2026
                    "IETF",
                    List.of("M. Ounsworth (Entrust)", "J. Gray (Entrust)", "M. Pala (OpenCA Labs)", "J. Klaussner (Bundesdruckerei)", "S. Fluhrer (Cisco)"),
                    "This document defines a composite public key structure that combines a classical public key with a post-quantum public key, specifically for use with the ML-DSA signature algorithm.",
                    "https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-18"
            );
        }
        
        // Mock data for another draft
        if ("draft-ietf-lamps-pq-keys".equals(draftIdentifier)) {
            return new RFCStatus(
                    "draft-ietf-lamps-pq-keys-04",
                    "Post-Quantum Key Agreement for the Internet Key Exchange Protocol Version 2 (IKEv2)",
                    "Active",
                    LocalDate.of(2026, 11, 30),
                    "IETF",
                    List.of("T. Pritikin (Cisco)", "V. Smyslov (Elven Labs)", "M. beadle (Zeuta)"),
                    "This document describes how to use post-quantum key exchange algorithms in IKEv2.",
                    "https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-keys-04"
            );
        }
        
        // If we don't have mock data for this draft, return a generic inactive status
        return new RFCStatus(
                draftIdentifier + "-00",
                "Unknown Draft",
                "Expired",
                LocalDate.now().minusDays(1),
                "IETF",
                List.of(),
                "This is a placeholder for an unknown draft.",
                "https://datatracker.ietf.org/doc/html/" + draftIdentifier
        );
    }

    @Override
    public boolean isExpiringSoon(String draftIdentifier, int daysThreshold) throws RFCMonitoringException {
        RFCStatus status = checkDraftStatus(draftIdentifier);
        LocalDate today = LocalDate.now();
        LocalDate expiryDate = status.getExpiresDate();
        
        // Calculate days until expiration
        long daysUntilExpiry = java.time.temporal.ChronoUnit.DAYS.between(today, expiryDate);
        
        // Consider expiring soon if within the threshold (and not already expired)
        return daysUntilExpiry >= 0 && daysUntilExpiry <= daysThreshold;
    }

    @Override
    public List<String> getMonitoredDrafts() {
        return new ArrayList<>(monitoredDrafts);
    }

    @Override
    public void registerDraft(String draftIdentifier, String draftUrl) {
        if (draftIdentifier != null && !draftIdentifier.isEmpty() && !monitoredDrafts.contains(draftIdentifier)) {
            monitoredDrafts.add(draftIdentifier);
        }
    }
}