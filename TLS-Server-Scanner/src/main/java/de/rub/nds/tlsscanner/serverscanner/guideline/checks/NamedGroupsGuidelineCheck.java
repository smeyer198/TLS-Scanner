/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import com.google.common.base.Joiner;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;

public class NamedGroupsGuidelineCheck extends GuidelineCheck {

    /**
     * Only these are allowed.
     */
    private List<NamedGroup> groups;
    /**
     * At least one of these has to be present.
     */
    private List<NamedGroup> required;
    private boolean tls13;
    private int minGroups = 0;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateStatus(SiteReport report) {
        List<NamedGroup> supportedGroups =
            this.tls13 ? report.getSupportedTls13Groups() : report.getSupportedNamedGroups();
        if (supportedGroups == null) {
            return Pair.of(GuidelineCheckStatus.UNCERTAIN, "Site Report is missing supported groups.");
        }
        if (required != null && !required.isEmpty()) {
            boolean found = false;
            for (NamedGroup group : supportedGroups) {
                if (this.required.contains(group)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return Pair.of(GuidelineCheckStatus.FAILED,
                    "Server is missing one of required groups:\n" + Joiner.on('\n').join(required));
            }
        }
        if (supportedGroups.size() < minGroups) {
            return Pair.of(GuidelineCheckStatus.FAILED,
                String.format("Server Supports less than %d groups.", this.minGroups));
        }
        List<NamedGroup> nonRecommended = new ArrayList<>();
        for (NamedGroup group : supportedGroups) {
            if (this.groups != null && !this.groups.contains(group)) {
                nonRecommended.add(group);
            }
        }
        if (nonRecommended.isEmpty()) {
            return Pair.of(GuidelineCheckStatus.PASSED, "Only listed groups are supported.");
        }
        return Pair.of(GuidelineCheckStatus.FAILED,
            "The following groups were supported but not recommended:\n" + Joiner.on('\n').join(nonRecommended));
    }

    public List<NamedGroup> getRequired() {
        return required;
    }

    public void setRequired(List<NamedGroup> required) {
        this.required = required;
    }

    public int getMinGroups() {
        return minGroups;
    }

    public void setMinGroups(int minGroups) {
        this.minGroups = minGroups;
    }

    public List<NamedGroup> getGroups() {
        return groups;
    }

    public void setGroups(List<NamedGroup> groups) {
        this.groups = groups;
    }

    public boolean isTls13() {
        return tls13;
    }

    public void setTls13(boolean tls13) {
        this.tls13 = tls13;
    }
}
