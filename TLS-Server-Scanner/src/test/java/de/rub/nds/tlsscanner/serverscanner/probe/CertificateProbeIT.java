/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class CertificateProbeIT extends AbstractProbeIT {

    public CertificateProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new CertificateProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_RSA_CERT, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ECDSA, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_DSS, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_GOST, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE);
    }

    @Override
    protected boolean executedAsPlanned() {
        return report.getCertificateChainList().size() == 1
                && report.getEcdsaPkGroupsStatic().size() == 0
                && report.getEcdsaPkGroupsEphemeral().size() == 0
                && report.getEcdsaPkGroupsTls13().size() == 0
                && report.getEcdsaSigGroupsStatic().size() == 0
                && report.getEcdsaSigGroupsEphemeral().size() == 0
                && report.getEcdsaSigGroupsTls13().size() == 0;
    }
}
