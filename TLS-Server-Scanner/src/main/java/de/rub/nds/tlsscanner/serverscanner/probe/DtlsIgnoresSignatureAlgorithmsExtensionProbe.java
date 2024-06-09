/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
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
import java.util.Collections;

public class DtlsIgnoresSignatureAlgorithmsExtensionProbe extends TlsServerProbe {

    private TestResult ignoresSignatureAlgorithms = TestResults.NOT_TESTED_YET;
    private boolean supportsCookieExchange = true;
    private SignatureAndHashAlgorithm certificateAlgorithm;

    public DtlsIgnoresSignatureAlgorithmsExtensionProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(
                parallelExecutor,
                TlsProbeType.IGNORES_SIGNATURE_ALGORITHMS_EXTENSION,
                configSelector);
    }

    @Override
    public void executeTest() {
        if (certificateAlgorithm == null) {
            ignoresSignatureAlgorithms = TestResults.COULD_NOT_TEST;
            return;
        }
        ignoresSignatureAlgorithms = testForIgnoringSignatureAlgorithmsExtension();
    }

    private TestResult testForIgnoringSignatureAlgorithmsExtension() {
        SignatureAndHashAlgorithm differentSignatureAndHashPair =
                getDifferentSignatureAndHashAlgorithm();

        Config config = configSelector.getBaseConfig();
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                Collections.singletonList(differentSignatureAndHashPair));

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
            return TestResults.FALSE;
        }

        return TestResults.TRUE;
    }

    private SignatureAndHashAlgorithm getDifferentSignatureAndHashAlgorithm() {
        if (certificateAlgorithm.name().contains("RSA")) {
            return SignatureAndHashAlgorithm.ECDSA_SHA256;
        }

        if (certificateAlgorithm.name().contains("ECDSA")) {
            return SignatureAndHashAlgorithm.DSA_SHA256;
        }

        if (certificateAlgorithm.name().contains("DSA")) {
            return SignatureAndHashAlgorithm.RSA_SHA256;
        }

        return null;
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportsCookieExchange = report.getCookieExchange();
        certificateAlgorithm = report.getSignatureAndHashAlgorithmCertificate();
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.DTLS_HELLO_VERIFY_REQUEST)
                .and(new ProbeRequirement<>(TlsProbeType.SIGNATURE_AND_HASH_ALGORITHM_CERTIFICATE))
                .and(new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS));
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.IGNORES_SIGNATURE_ALGORITHMS_EXTENSION, ignoresSignatureAlgorithms);
    }
}
