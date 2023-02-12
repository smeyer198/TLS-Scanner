/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/** Represents a {@link Requirement} for required executed {@link TlsProbeType}s. */
public class ProbeRequirement extends Requirement {
    private final TlsProbeType[] probes;
    private List<TlsProbeType> missing;

    /**
     * @param probes the required {@link TlsProbeType}. Any amount possible.
     */
    public ProbeRequirement(TlsProbeType... probes) {
        super();
        this.probes = probes;
        this.missing = new ArrayList<>();
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if ((probes == null) || (probes.length == 0)) {
            return true;
        }
        boolean returnValue = true;
        missing = new ArrayList<>();
        for (TlsProbeType probe : probes) {
            if (report.isProbeAlreadyExecuted(probe) == false) {
                returnValue = false;
                missing.add(probe);
            }
        }
        return returnValue;
    }

    @Override
    public String toString() {
        String returnString = "";
        if (probes.length == 1) {
            returnString += "Probe: ";

        } else {
            returnString += "Probes: ";
        }
        return returnString +=
                Arrays.stream(probes).map(TlsProbeType::name).collect(Collectors.joining(", "));
    }

    /**
     * @return the required {@link TlsProbeType}s.
     */
    public TlsProbeType[] getRequirement() {
        return probes;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new ProbeRequirement(
                                    this.missing.toArray(new TlsProbeType[this.missing.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
