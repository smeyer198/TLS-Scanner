/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DtlsRetransmissionsResult extends ProbeResult {

    private TestResult sendsRetransmissions;
    private TestResult processesRetransmissions;

    public DtlsRetransmissionsResult(TestResult sendsRetransmissions, TestResult processesRetransmissions) {
        super(ProbeType.DTLS_RETRANSMISSIONS);
        this.sendsRetransmissions = sendsRetransmissions;
        this.processesRetransmissions = processesRetransmissions;

    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SENDS_RETRANSMISSIONS, sendsRetransmissions);
        report.putResult(AnalyzedProperty.PROCESSES_RETRANSMISSIONS, processesRetransmissions);
    }

}
