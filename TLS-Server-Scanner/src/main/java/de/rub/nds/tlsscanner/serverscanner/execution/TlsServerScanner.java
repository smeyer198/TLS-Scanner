/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.execution;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.execution.ScanJob;
import de.rub.nds.scanner.core.execution.Scanner;
import de.rub.nds.scanner.core.execution.ThreadedScanJobExecutor;
import de.rub.nds.scanner.core.guideline.Guideline;
import de.rub.nds.scanner.core.guideline.GuidelineChecker;
import de.rub.nds.scanner.core.guideline.GuidelineIO;
import de.rub.nds.scanner.core.passive.StatsWriter;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.CbcIvExtractor;
import de.rub.nds.tlsscanner.core.passive.DhPublicKeyExtractor;
import de.rub.nds.tlsscanner.core.passive.DtlsRetransmissionsExtractor;
import de.rub.nds.tlsscanner.core.passive.EcPublicKeyExtractor;
import de.rub.nds.tlsscanner.core.passive.RandomExtractor;
import de.rub.nds.tlsscanner.core.trust.TrustAnchorManager;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.connectivity.ConnectivityChecker;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.*;
import de.rub.nds.tlsscanner.serverscanner.passive.CookieExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.DestinationPortExtractor;
import de.rub.nds.tlsscanner.serverscanner.passive.SessionIdExtractor;
import de.rub.nds.tlsscanner.serverscanner.probe.*;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.report.rating.DefaultRatingLoader;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsServerScanner
        extends Scanner<ServerReport, TlsServerProbe, AfterProbe<ServerReport>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigSelector configSelector;
    private final ParallelExecutor parallelExecutor;
    private final ServerScannerConfig config;
    private boolean closeAfterFinishParallel;

    public TlsServerScanner(ServerScannerConfig config) {
        super(config.getExecutorConfig().getProbes());
        this.config = config;
        closeAfterFinishParallel = true;
        parallelExecutor =
                new ParallelExecutor(
                        config.getExecutorConfig().getOverallThreads(),
                        3,
                        new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        setCallbacks();
        fillProbeLists();
    }

    public TlsServerScanner(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(config.getExecutorConfig().getProbes());
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        this.parallelExecutor = parallelExecutor;
        closeAfterFinishParallel = false;
        setCallbacks();
        fillProbeLists();
    }

    public TlsServerScanner(
            ServerScannerConfig config,
            ParallelExecutor parallelExecutor,
            List<TlsServerProbe> probeList,
            List<AfterProbe<ServerReport>> afterList) {
        super(probeList.stream().map(ScannerProbe::getType).collect(Collectors.toList()));
        this.probeList.addAll(probeList);
        this.afterList.addAll(afterList);
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.configSelector = new ConfigSelector(config, parallelExecutor);
        closeAfterFinishParallel = false;
        setDefaultProbeWriter();
        setCallbacks();
    }

    private void setCallbacks() {
        if (config.getCallbackDelegate().getBeforeTransportPreInitCallback() != null
                && parallelExecutor.getDefaultBeforeTransportPreInitCallback() == null) {
            parallelExecutor.setDefaultBeforeTransportPreInitCallback(
                    config.getCallbackDelegate().getBeforeTransportPreInitCallback());
        }
        if (config.getCallbackDelegate().getBeforeTransportInitCallback() != null
                && parallelExecutor.getDefaultBeforeTransportInitCallback() == null) {
            parallelExecutor.setDefaultBeforeTransportInitCallback(
                    config.getCallbackDelegate().getBeforeTransportInitCallback());
        }
        if (config.getCallbackDelegate().getAfterTransportInitCallback() != null
                && parallelExecutor.getDefaultAfterTransportInitCallback() == null) {
            parallelExecutor.setDefaultAfterTransportInitCallback(
                    config.getCallbackDelegate().getAfterTransportInitCallback());
        }
        if (config.getCallbackDelegate().getAfterExecutionCallback() != null
                && parallelExecutor.getDefaultAfterExecutionCallback() == null) {
            parallelExecutor.setDefaultAfterExecutionCallback(
                    config.getCallbackDelegate().getAfterExecutionCallback());
        }
    }

    @Override
    protected void fillProbeLists() {
        ProtocolVersionProbe protocolVersionProbe =
                new ProtocolVersionProbe(configSelector, parallelExecutor);
        protocolVersionProbe.setWriter(new StatsWriter());
        addProbeToProbeList(protocolVersionProbe);

        CipherSuiteProbe cipherSuiteProbe = new CipherSuiteProbe(configSelector, parallelExecutor);
        cipherSuiteProbe.setWriter(new StatsWriter());
        addProbeToProbeList(cipherSuiteProbe);

        DtlsCookieExchangeProbe cookieExchangeProbe =
                new DtlsCookieExchangeProbe(configSelector, parallelExecutor);
        cookieExchangeProbe.setWriter(new StatsWriter());
        addProbeToProbeList(cookieExchangeProbe);

        DtlsClientAuthenticationProbe clientAuthenticationProbe =
                new DtlsClientAuthenticationProbe(configSelector, parallelExecutor);
        clientAuthenticationProbe.setWriter(new StatsWriter());
        addProbeToProbeList(clientAuthenticationProbe);

        DtlsCertificateAlgorithmProbe algorithmProbe =
                new DtlsCertificateAlgorithmProbe(configSelector, parallelExecutor);
        algorithmProbe.setWriter(new StatsWriter());
        addProbeToProbeList(algorithmProbe);

        DtlsIgnoresSignatureAlgorithmsExtensionProbe ignoresSignatureAlgorithmsExtensionProbe =
                new DtlsIgnoresSignatureAlgorithmsExtensionProbe(configSelector, parallelExecutor);
        ignoresSignatureAlgorithmsExtensionProbe.setWriter(new StatsWriter());
        addProbeToProbeList(ignoresSignatureAlgorithmsExtensionProbe);

        DtlsOverlappingFragmentsProbe overlappingFragmentsProbe =
                new DtlsOverlappingFragmentsProbe(configSelector, parallelExecutor);
        overlappingFragmentsProbe.setWriter(new StatsWriter());
        addProbeToProbeList(overlappingFragmentsProbe);
    }

    private void setDefaultProbeWriter() {
        for (TlsServerProbe probe : probeList) {
            StatsWriter statsWriter = new StatsWriter();
            statsWriter.addExtractor(new CookieExtractor());
            statsWriter.addExtractor(new RandomExtractor());
            statsWriter.addExtractor(new DhPublicKeyExtractor());
            statsWriter.addExtractor(new EcPublicKeyExtractor());
            statsWriter.addExtractor(new CbcIvExtractor());
            statsWriter.addExtractor(new SessionIdExtractor());
            statsWriter.addExtractor(new DtlsRetransmissionsExtractor());
            statsWriter.addExtractor(new DestinationPortExtractor());
            probe.setWriter(statsWriter);
        }
    }

    public ServerReport scan() {
        LOGGER.debug("Initializing TrustAnchorManager");
        TrustAnchorManager.getInstance();
        LOGGER.debug("Finished TrustAnchorManager initialization");

        boolean isConnectable = false;
        boolean speaksProtocol = false;
        boolean isHandshaking = false;
        ProtocolType protocolType = getProtocolType();
        ThreadedScanJobExecutor<ServerReport, TlsServerProbe, AfterProbe<ServerReport>> executor =
                null;
        // TODO Kind of hacky - this extracts the hosts from the client delegate - otherwise its not
        // initialized
        ServerReport serverReport =
                new ServerReport(
                        config.getClientDelegate().getExtractedHost(),
                        config.getClientDelegate().getExtractedPort());
        serverReport.setProtocolType(protocolType);

        if (isConnectable()) {
            isConnectable = true;
            LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
            configSelector.findWorkingConfigs();
            serverReport.setConfigProfileIdentifier(configSelector.getConfigProfileIdentifier());
            serverReport.setConfigProfileIdentifierTls13(
                    configSelector.getConfigProfileIdentifierTls13());
            if (configSelector.isSpeaksProtocol()) {
                speaksProtocol = true;
                LOGGER.debug(
                        config.getClientDelegate().getHost() + " speaks " + protocolType.getName());
                if (configSelector.isIsHandshaking()) {
                    isHandshaking = true;
                    LOGGER.debug(config.getClientDelegate().getHost() + " is handshaking");

                    ScanJob<ServerReport, TlsServerProbe, AfterProbe<ServerReport>> job =
                            new ScanJob<>(probeList, afterList);
                    executor =
                            new ThreadedScanJobExecutor<>(
                                    config.getExecutorConfig(),
                                    job,
                                    config.getExecutorConfig().getParallelProbes(),
                                    config.getClientDelegate().getHost());
                    long scanStartTime = System.currentTimeMillis();
                    serverReport = executor.execute(serverReport);
                    SiteReportRater rater;
                    try {
                        rater = DefaultRatingLoader.getServerReportRater("en");
                        ScoreReport scoreReport = rater.getScoreReport(serverReport.getResultMap());
                        serverReport.setScore(scoreReport.getScore());
                        serverReport.setScoreReport(scoreReport);
                    } catch (IOException | JAXBException | XMLStreamException ex) {
                        LOGGER.error("Could not retrieve scoring results");
                    }
                    if (protocolType != ProtocolType.DTLS) {
                        executeGuidelineEvaluation(serverReport);
                    }
                    long scanEndTime = System.currentTimeMillis();
                    serverReport.setScanStartTime(scanStartTime);
                    serverReport.setScanEndTime(scanEndTime);
                }
            }
        }

        serverReport.setServerIsAlive(isConnectable);
        serverReport.setSpeaksProtocol(speaksProtocol);
        serverReport.setIsHandshaking(isHandshaking);

        if (executor != null) {
            executor.shutdown();
        }
        closeParallelExecutorIfNeeded();

        return serverReport;
    }

    private void executeGuidelineEvaluation(ServerReport report) {
        LOGGER.debug("Evaluating guidelines...");
        List<String> guidelines = Arrays.asList("bsi.xml", "nist.xml");
        GuidelineIO<ServerReport> guidelineIO;
        try {
            guidelineIO =
                    new GuidelineIO<>(
                            TlsAnalyzedProperty.class,
                            Set.of(
                                    AnalyzedPropertyGuidelineCheck.class,
                                    CertificateAgilityGuidelineCheck.class,
                                    CertificateCurveGuidelineCheck.class,
                                    CertificateSignatureCheck.class,
                                    CertificateValidityGuidelineCheck.class,
                                    CertificateVersionGuidelineCheck.class,
                                    CipherSuiteGuidelineCheck.class,
                                    ExtendedKeyUsageCertificateCheck.class,
                                    ExtensionGuidelineCheck.class,
                                    HashAlgorithmsGuidelineCheck.class,
                                    HashAlgorithmStrengthCheck.class,
                                    KeySizeCertGuidelineCheck.class,
                                    KeyUsageCertificateCheck.class,
                                    NamedGroupsGuidelineCheck.class,
                                    SignatureAlgorithmsCertificateGuidelineCheck.class,
                                    SignatureAlgorithmsGuidelineCheck.class,
                                    SignatureAndHashAlgorithmsCertificateGuidelineCheck.class,
                                    SignatureAndHashAlgorithmsGuidelineCheck.class));
        } catch (JAXBException e) {
            LOGGER.error("Unable to initialize JAXB context while reading guidelines", e);
            return;
        }
        for (String guidelineName : guidelines) {
            try {
                InputStream guideLineStream =
                        TlsServerScanner.class.getResourceAsStream("/guideline/" + guidelineName);
                Guideline<ServerReport> guideline = guidelineIO.read(guideLineStream);
                LOGGER.debug("Evaluating guideline {} ...", guideline.getName());
                GuidelineChecker<ServerReport> checker = new GuidelineChecker<>(guideline);
                checker.fillReport(report);
            } catch (JAXBException | IOException | XMLStreamException ex) {
                LOGGER.error("Could not read guideline", ex);
            }
        }
        LOGGER.debug("Finished evaluating guidelines");
    }

    private void closeParallelExecutorIfNeeded() {
        if (closeAfterFinishParallel) {
            parallelExecutor.shutdown();
        }
    }

    private ProtocolType getProtocolType() {
        if (config.getDtlsDelegate().isDTLS()) {
            return ProtocolType.DTLS;
        } else if (config.getStartTlsDelegate().getStarttlsType() != StarttlsType.NONE) {
            return ProtocolType.STARTTLS;
        } else {
            return ProtocolType.TLS;
        }
    }

    public boolean isConnectable() {
        try {
            Config tlsConfig = config.createConfig();
            ConnectivityChecker checker =
                    new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
            return checker.isConnectable();
        } catch (Exception e) {
            LOGGER.warn("Could not test if we can connect to the server", e);
            return false;
        }
    }

    public void setCloseAfterFinishParallel(boolean closeAfterFinishParallel) {
        this.closeAfterFinishParallel = closeAfterFinishParallel;
    }

    public boolean isCloseAfterFinishParallel() {
        return closeAfterFinishParallel;
    }
}
