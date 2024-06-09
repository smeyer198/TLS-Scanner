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
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsCookieExchangeProbe extends TlsServerProbe {

    private TestResult supportsDtlsCookieExchange = TestResults.NOT_TESTED_YET;

    public DtlsCookieExchangeProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_HELLO_VERIFY_REQUEST, configSelector);

        register(TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE);
    }

    @Override
    public void executeTest() {
        supportsDtlsCookieExchange = testForCookieExchange();
    }

    private TestResult testForCookieExchange() {
        // Copied from
        // https://github.com/tls-attacker/TLS-Scanner/blob/main/TLS-Server-Scanner/src/main/java/de/rub/nds/tlsscanner/serverscanner/probe/DtlsHelloVerifyRequestProbe.java
        Config config = configSelector.getBaseConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        State state = new State(config, trace);
        executeState(state);
        HandshakeMessage<?> message =
                WorkflowTraceUtil.getLastReceivedMessage(
                        HandshakeMessageType.HELLO_VERIFY_REQUEST, state.getWorkflowTrace());
        if (message != null) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS);
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (supportsDtlsCookieExchange == TestResults.TRUE) {
            report.setCookieExchange(true);
        } else if (supportsDtlsCookieExchange == TestResults.FALSE) {
            report.setCookieExchange(false);
        }
        put(TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE, supportsDtlsCookieExchange);
    }
}
