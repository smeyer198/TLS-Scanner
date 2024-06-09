/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsCertificateAlgorithmProbe extends TlsServerProbe {

    private boolean supportsCookieExchange = true;
    private SignatureAndHashAlgorithm certificateAlgorithm;

    public DtlsCertificateAlgorithmProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(
                parallelExecutor,
                TlsProbeType.SIGNATURE_AND_HASH_ALGORITHM_CERTIFICATE,
                configSelector);

        register(TlsAnalyzedProperty.CERTIFICATE_SIGNATURE_AND_HASH_ALGORITHM);
    }

    @Override
    public void executeTest() {
        certificateAlgorithm = testForSignatureAndHashAlgorithmInCertificate();
    }

    private SignatureAndHashAlgorithm testForSignatureAndHashAlgorithmInCertificate() {
        Config config = configSelector.getBaseConfig();

        WorkflowTrace trace = new WorkflowTrace();

        if (supportsCookieExchange) {
            trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        }

        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = new State(config, trace);
        executeState(state);

        CertificateMessage message = trace.getFirstReceivedMessage(CertificateMessage.class);

        if (message == null) {
            return null;
        }

        return message.getCertificateKeyPair().getSignatureAndHashAlgorithm();
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportsCookieExchange = report.getCookieExchange();
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.DTLS_HELLO_VERIFY_REQUEST)
                .and(new ProbeRequirement<>(TlsProbeType.CIPHER_SUITE))
                .and(new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS));
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (certificateAlgorithm != null) {
            put(TlsAnalyzedProperty.CERTIFICATE_SIGNATURE_AND_HASH_ALGORITHM, certificateAlgorithm);
        } else {
            put(
                    TlsAnalyzedProperty.CERTIFICATE_SIGNATURE_AND_HASH_ALGORITHM,
                    TestResults.COULD_NOT_TEST);
        }
        report.setSignatureAndHashAlgorithmCertificate(certificateAlgorithm);
    }
}
