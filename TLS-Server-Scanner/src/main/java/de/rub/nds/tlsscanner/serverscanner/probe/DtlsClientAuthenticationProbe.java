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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsClientAuthenticationProbe extends TlsServerProbe {

    private boolean supportsCookieExchange = true;
    private TestResult requiresClientAuthentication = TestResults.NOT_TESTED_YET;

    public DtlsClientAuthenticationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CLIENT_AUTHENTICATION, configSelector);

        register(TlsAnalyzedProperty.REQUIRES_CLIENT_AUTHENTICATION);
    }

    @Override
    public void executeTest() {
        requiresClientAuthentication = testForClientAuthentication();
    }

    public TestResult testForClientAuthentication() {
        Config config = configSelector.getBaseConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);

        WorkflowTrace trace = new WorkflowTrace();

        if (supportsCookieExchange) {
            trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        }
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));

        // Assume Client Authentication
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new ReceiveAction(new FinishedMessage()));

        State state = new State(config, trace);
        executeState(state);

        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.CERTIFICATE_REQUEST, state.getWorkflowTrace())) {
            if (WorkflowTraceUtil.didReceiveMessage(
                    HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
                return TestResults.TRUE;
            }
            // Client Certificate is not validated by server
            return TestResults.PARTIALLY;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportsCookieExchange = report.getCookieExchange();
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.DTLS_HELLO_VERIFY_REQUEST)
                .and(new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS));
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (requiresClientAuthentication == TestResults.TRUE) {
            report.setClientAuthentication(true);
        } else if (requiresClientAuthentication == TestResults.FALSE) {
            report.setClientAuthentication(false);
        }
        put(TlsAnalyzedProperty.REQUIRES_CLIENT_AUTHENTICATION, requiresClientAuthentication);
    }
}
