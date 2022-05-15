/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

public class ExtensionProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private boolean supportsTls13;

    private List<ExtensionType> allSupportedExtensions;
    private TestResult extendedMasterSecret = TestResults.FALSE;
    private TestResult encryptThenMac = TestResults.FALSE;
    private TestResult secureRenegotiation = TestResults.FALSE;
    private TestResult sessionTickets = TestResults.FALSE;
    private TestResult certStatusRequest = TestResults.FALSE;
    private TestResult certStatusRequestV2 = TestResults.FALSE;

    public ExtensionProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.EXTENSIONS, config);
        super.register(TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
            TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
            TlsAnalyzedProperty.SUPPORTS_SESSION_TICKETS, TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST,
            TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS);
    }

    @Override
    public void executeTest() {
        allSupportedExtensions = getSupportedExtensions();
    }

    public List<ExtensionType> getSupportedExtensions() {
        Set<ExtensionType> allSupportedExtensions = new HashSet<>();
        List<ExtensionType> commonExtensions = getCommonExtension(ProtocolVersion.TLS12, suite -> true);
        if (commonExtensions != null) {
            allSupportedExtensions.addAll(commonExtensions);
        }
        commonExtensions = getCommonExtension(ProtocolVersion.TLS12, CipherSuite::isCBC);
        if (commonExtensions != null) {
            allSupportedExtensions.addAll(commonExtensions);
        }
        if (supportsTls13) {
            commonExtensions = getCommonExtension(ProtocolVersion.TLS13, CipherSuite::isTLS13);
            if (commonExtensions != null) {
                allSupportedExtensions.addAll(commonExtensions);
            }
        }
        return new ArrayList<>(allSupportedExtensions);
    }

    private List<ExtensionType> getCommonExtension(ProtocolVersion highestVersion,
        Predicate<CipherSuite> cipherSuitePredicate) {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>(Arrays.asList(CipherSuite.values()));
        cipherSuites.removeIf(cipherSuitePredicate.negate());
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        // Don't send extensions if we are in SSLv2
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddHeartbeatExtension(true);
        tlsConfig.setAddMaxFragmentLengthExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddAlpnExtension(true);
        List<String> alpnProtocols = new LinkedList<>();
        for (AlpnProtocol protocol : AlpnProtocol.values()) {
            alpnProtocols.add(protocol.getConstant());
        }
        tlsConfig.setDefaultProposedAlpnProtocols(alpnProtocols);
        tlsConfig.setAddEncryptThenMacExtension(true);
        tlsConfig.setAddExtendedMasterSecretExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSessionTicketTLSExtension(true);
        tlsConfig.setAddExtendedRandomExtension(true);
        tlsConfig.setAddTruncatedHmacExtension(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);

        // Certificate Status v2 shenanigans
        RequestItemV2 emptyRequest = new RequestItemV2(2, 0, 0, 0, new byte[0]);
        List<RequestItemV2> requestV2List = new LinkedList<>();
        requestV2List.add(emptyRequest);
        tlsConfig.setStatusRequestV2RequestList(requestV2List);
        tlsConfig.setAddCertificateStatusRequestV2Extension(true);

        if (highestVersion.isTLS13()) {
            tlsConfig.setAddSupportedVersionsExtension(true);
            tlsConfig.setAddKeyShareExtension(true);
        }

        List<NamedGroup> nameGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(nameGroups);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return new ArrayList<>(state.getTlsContext().getNegotiatedExtensionSet());
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportsTls13 = TestResults.TRUE.equals(report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3));
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS,
            new ListResult<ExtensionType>(allSupportedExtensions, "SUPPORTED_EXTENSIONS"));
        if (allSupportedExtensions != null) {
            for (ExtensionType type : allSupportedExtensions) {
                if (type == ExtensionType.ENCRYPT_THEN_MAC)
                    encryptThenMac = TestResults.TRUE;
                if (type == ExtensionType.EXTENDED_MASTER_SECRET)
                    extendedMasterSecret = TestResults.TRUE;
                if (type == ExtensionType.RENEGOTIATION_INFO)
                    secureRenegotiation = TestResults.TRUE;
                if (type == ExtensionType.SESSION_TICKET)
                    sessionTickets = TestResults.TRUE;
                if (type == ExtensionType.STATUS_REQUEST)
                    certStatusRequest = TestResults.TRUE;
                if (type == ExtensionType.STATUS_REQUEST_V2)
                    certStatusRequestV2 = TestResults.TRUE;
            }
        } else {
            encryptThenMac = TestResults.COULD_NOT_TEST;
            extendedMasterSecret = TestResults.COULD_NOT_TEST;
            secureRenegotiation = TestResults.COULD_NOT_TEST;
            sessionTickets = TestResults.COULD_NOT_TEST;
            certStatusRequest = TestResults.COULD_NOT_TEST;
            certStatusRequestV2 = TestResults.COULD_NOT_TEST;
        }
        super.put(TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, extendedMasterSecret);
        super.put(TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, encryptThenMac);
        super.put(TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, secureRenegotiation);
        super.put(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKETS, sessionTickets);
        super.put(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, certStatusRequest);
        super.put(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, certStatusRequestV2);
    }
}
