/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.ReportPrinter;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.PropertyResultRecommendation;
import de.rub.nds.scanner.core.report.rating.Recommendation;
import de.rub.nds.scanner.core.report.rating.Recommendations;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestamp;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.RandomType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateIssue;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.padding.PaddingOracleStrength;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.report.CipherSuiteGrade;
import de.rub.nds.tlsscanner.core.report.CipherSuiteRater;
import de.rub.nds.tlsscanner.core.report.EntropyReport;
import de.rub.nds.tlsscanner.core.trust.TrustAnchorManager;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.core.vector.statistics.ResponseCounter;
import de.rub.nds.tlsscanner.core.vector.statistics.VectorContainer;
import de.rub.nds.tlsscanner.serverscanner.afterprobe.prime.CommonDhValues;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaCertificateType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.HandshakeFailureReasons;
import de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation.SimulatedClientResult;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidcurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.probe.namedgroup.NamedGroupWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.result.cca.CcaTestResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ocsp.OcspCertificateResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackProbabilities;
import de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack.RaccoonAttackPskProbabilities;
import de.rub.nds.tlsscanner.serverscanner.report.rating.DefaultRatingLoader;
import java.security.PublicKey;
import java.text.DecimalFormat;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.Period;
import org.joda.time.format.PeriodFormat;

public class ServerReportPrinter extends ReportPrinter<ServerReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String hsClientFormat = "%-28s";
    private final String hsVersionFormat = "%-14s";
    private final String hsCipherSuiteFormat = "%-52s";
    private final String hsForwardSecrecyFormat = "%-19s";
    private final String hsKeyLengthFormat = "%-17s";

    public ServerReportPrinter(
            ServerReport report,
            ScannerDetail detail,
            PrintingScheme scheme,
            boolean printColorful) {
        super(detail, scheme, printColorful, report);
    }

    @Override
    public String getFullReport() {
        StringBuilder builder = new StringBuilder();
        builder.append("Report for ");
        builder.append(report.getHost() + ":" + report.getPort());
        builder.append("\n");
        if (Objects.equals(report.getServerIsAlive(), Boolean.FALSE)) {
            builder.append("Cannot reach the Server. Is it online?");
            return builder.toString();
        }
        if (Objects.equals(report.getSpeaksProtocol(), Boolean.FALSE)) {
            builder.append(
                    "Server does not seem to support "
                            + report.getProtocolType().getName()
                            + " on the scanned port");
            return builder.toString();
        }
        appendProtocolVersions(builder);
        appendCipherSuites(builder);
        /*appendExtensions(builder);
        appendCompressions(builder);
        appendEcPointFormats(builder);
        appendRecordFragmentation(builder);
        appendAlpn(builder);
        appendIntolerances(builder);
        appendHelloRetry(builder);
        appendAttackVulnerabilities(builder);
        appendAlpacaAttack(builder);
        appendBleichenbacherResults(builder);
        appendPaddingOracleResults(builder);
        // appendSessionTicketZeroKeyDetails(builder);
        appendDirectRaccoonResults(builder);
        appendInvalidCurveResults(builder);
        appendRaccoonAttackDetails(builder);
        // appendGcm(builder);
        // appendRfc(builder);
        appendCertificates(builder);
        appendOcsp(builder);
        appendCertificateTransparency(builder);
        appendSession(builder);
        appendRenegotiation(builder);
        appendHttps(builder);
        appendRandomness(builder);
        appendPublicKeyIssues(builder);
        appendClientAuthentication(builder);
        if (report.getProtocolType() == ProtocolType.DTLS) {
            appendDtlsSpecificResults(builder);
        }
        appendScoringResults(builder);
        appendRecommendations(builder);
        if (report.getProtocolType() != ProtocolType.DTLS) {
            appendGuidelines(builder);
        }
        appendPerformanceData(builder);
        appendMissingProbesRequirements(builder);*/
        appendDtlsOverlappingFragmentResults(builder);

        return builder.toString();
    }

    private void appendDtlsOverlappingFragmentResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Overlapping Fragments");
        prettyAppend(
                builder,
                "Supports DTLS Cookie Exchange",
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE);
        prettyAppend(
                builder,
                "Requires Client Authentication",
                TlsAnalyzedProperty.REQUIRES_CLIENT_AUTHENTICATION);

        prettyAppend(
                builder,
                "Accepts ClientHello Consecutive  Fragments",
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_CONSECUTIVE_FRAGMENTS);
        prettyAppend(
                builder,
                "Accepts ClientHello Subsequent Fragments",
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_SUBSEQUENT_FRAGMENTS);
        prettyAppend(
                builder,
                "Accepts ClientHello Subsequent Fragments",
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_EXTENDED_SUBSEQUENT_FRAGMENTS);

        prettyAppend(
                builder,
                "Accepts ClientKeyExchange Consecutive  Fragments",
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_CONSECUTIVE_FRAGMENTS);
        prettyAppend(
                builder,
                "Accepts ClientKeyExchange Subsequent  Fragments",
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_SUBSEQUENT_FRAGMENTS);
        prettyAppend(
                builder,
                "Accepts ClientKeyExchange Extended Subsequent  Fragments",
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_EXTENDED_SUBSEQUENT_FRAGMENTS);

        // Version
        prettyAppend(
                builder,
                "Consecutive Version Type A Original Order",
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Consecutive Version Type A Reversed Order",
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Consecutive Version Type B Original Order",
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Consecutive Version Type B Reversed Order",
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_B_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Subsequent Version Type A Original Order",
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Subsequent Version Type A Reversed Order",
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Subsequent Version Type B Original Order",
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Subsequent Version Type B Reversed Order",
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_B_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Extended Subsequent Version Type A Original Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Extended Subsequent Version Type A Reversed Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Extended Subsequent Version Type B Original Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Extended Subsequent Version Type B Reversed Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_B_REVERSED_ORDER);

        // CipherSuites
        prettyAppend(
                builder,
                "Consecutive Cipher Suite Type A Original Order",
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Consecutive Cipher Suite Type A Reversed Order",
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Consecutive Cipher Suite Type B Original Order",
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Consecutive Cipher Suite Type B Reversed Order",
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_B_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Subsequent Cipher Suite Type A Original Order",
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Subsequent Cipher Suite Type A Reversed Order",
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Subsequent Cipher Suite Type B Original Order",
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Subsequent Cipher Suite Type B Reversed Order",
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_B_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Extended Subsequent Cipher Suite Type A Original Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Extended Subsequent Cipher Suite Type A Reversed Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Extended Subsequent Cipher Suite Type B Original Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Extended Subsequent Cipher Suite Type B Reversed Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_B_REVERSED_ORDER);

        // SignatureAndHashAlgorithms
        prettyAppend(
                builder,
                "Consecutive SigAndHash Type A Original Order",
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Consecutive SigAndHash Type A Reversed Order",
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Consecutive SigAndHash Type B Original Order",
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Consecutive SigAndHash Type B Reversed Order",
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_B_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Subsequent SigAndHash Type A Original Order",
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Subsequent SigAndHash Type A Reversed Order",
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Subsequent SigAndHash Type B Original Order",
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Subsequent SigAndHash Type B Reversed Order",
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_B_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Extended Subsequent SigAndHash Type A Original Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Extended Subsequent SigAndHash Type A Reversed Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_A_REVERSED_ORDER);

        prettyAppend(
                builder,
                "Extended Subsequent SigAndHash Type B Original Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "Extended Subsequent SigAndHash Type B Reversed Order",
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_B_REVERSED_ORDER);

        // ClientKeyExchange
        prettyAppend(
                builder,
                "RSA ClientKeyExchange Original Order",
                TlsAnalyzedProperty.RSA_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "RSA ClientKeyExchange Reversed Order",
                TlsAnalyzedProperty.RSA_CLIENT_KEY_EXCHANGE_REVERSED_ORDER);

        prettyAppend(
                builder,
                "DH ClientKeyExchange Original Order",
                TlsAnalyzedProperty.DH_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "DH ClientKeyExchange Reversed Order",
                TlsAnalyzedProperty.DH_CLIENT_KEY_EXCHANGE_REVERSED_ORDER);

        prettyAppend(
                builder,
                "ECDH ClientKeyExchange Original Order",
                TlsAnalyzedProperty.ECDH_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER);
        prettyAppend(
                builder,
                "ECDH ClientKeyExchange Reversed Order",
                TlsAnalyzedProperty.ECDH_CLIENT_KEY_EXCHANGE_REVERSED_ORDER);
    }

    private void appendMissingProbesRequirements(StringBuilder builder) {
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppendHeading(
                    builder, "Unexecuted Probes and the respectively missing Requirements");
            for (ScannerProbe<ServerReport, ?> unexecutedProbe : report.getUnexecutedProbes())
                prettyAppend(
                        builder,
                        unexecutedProbe.getProbeName(),
                        unexecutedProbe
                                .getRequirements()
                                .getUnfulfilledRequirements(report)
                                .stream()
                                .map(Object::toString)
                                .collect(Collectors.joining(";")));
        }
    }

    private void appendDtlsSpecificResults(StringBuilder builder) {
        prettyAppendHeading(builder, "DTLS Features");
        prettyAppend(builder, "Server changes port", TlsAnalyzedProperty.CHANGES_PORT);
        if (report.getResult(TlsAnalyzedProperty.CHANGES_PORT) == TestResults.TRUE) {
            prettyAppend(
                    builder, "-To random ports", TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS);
        }
        prettyAppend(builder, "Supports reordering", TlsAnalyzedProperty.SUPPORTS_REORDERING);

        prettyAppendHeading(builder, "DTLS Fragmentation");
        prettyAppend(
                builder, "Supports fragmentation", TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION);
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION)
                == TestResults.PARTIALLY) {
            if (report.getResult(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION)
                    == TestResults.TRUE) {
                prettyAppend(builder, "-Requires Max Fragment Length extension");
            } else {
                prettyAppend(builder, "-After cookie exchange");
            }
        }
        prettyAppend(
                builder,
                "Supports fragmentation with individual transport packets",
                TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS);
        if (report.getResult(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS)
                == TestResults.PARTIALLY) {
            if (report.getResult(
                            TlsAnalyzedProperty
                                    .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION)
                    == TestResults.TRUE) {
                prettyAppend(builder, "-Requires Max Fragment Length extension");
            } else {
                prettyAppend(builder, "-After cookie exchange");
            }
        }

        prettyAppendHeading(builder, "DTLS Hello Verify Request");
        prettyAppend(builder, "HVR Retransmissions", TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS);
        if (report.getCookieLength() != null) {
            prettyAppend(builder, "Cookie length", "" + report.getCookieLength());
        } else {
            prettyAppend(builder, "Cookie length", TlsAnalyzedProperty.HAS_COOKIE_CHECKS);
        }
        prettyAppend(builder, "Checks cookie", TlsAnalyzedProperty.HAS_COOKIE_CHECKS);
        prettyAppend(builder, "Cookie is influenced by");
        prettyAppend(builder, "-ip", TlsAnalyzedProperty.USES_IP_ADDRESS_FOR_COOKIE);
        prettyAppend(builder, "-port", TlsAnalyzedProperty.USES_PORT_FOR_COOKIE);
        prettyAppend(builder, "-version", TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE);
        prettyAppend(builder, "-random", TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE);
        prettyAppend(builder, "-session id", TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE);
        prettyAppend(builder, "-cipher suites", TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE);
        prettyAppend(builder, "-compressions", TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE);

        prettyAppendHeading(builder, "DTLS Message Sequence Number");
        prettyAppend(
                builder,
                "Accepts start with invalid msg seq",
                TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE);
        prettyAppend(
                builder,
                "Misses msg seq checks",
                TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS);
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppend(
                    builder,
                    "-Accepts: 0,4,5,6",
                    TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE);
            prettyAppend(
                    builder,
                    "-Accepts: 0,4,8,9",
                    TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE);
            prettyAppend(
                    builder,
                    "-Accepts: 0,8,4,5",
                    TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES);
        }

        prettyAppendHeading(builder, "DTLS Retransmissions");
        prettyAppend(builder, "Sends retransmissions", TlsAnalyzedProperty.SENDS_RETRANSMISSIONS);
        prettyAppend(
                builder,
                "Processes retransmissions",
                TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS);
        prettyAppend(
                builder,
                "Total retransmissions received",
                "" + report.getTotalReceivedRetransmissions());
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                && report.getRetransmissionCounters() != null) {
            for (HandshakeMessageType type : report.getRetransmissionCounters().keySet()) {
                prettyAppend(
                        builder,
                        "-" + type.getName(),
                        "" + report.getRetransmissionCounters().get(type));
            }
        }

        prettyAppendHeading(builder, "DTLS Bugs");
        prettyAppend(
                builder,
                "Accepts Finished with Epoch 0",
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED);
        prettyAppend(
                builder,
                "Accepts App Data with Epoch 0",
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA);
        prettyAppend(builder, "Early Finished", TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG);

        List<ApplicationProtocol> applications = report.getSupportedApplicationProtocols();
        if (applications != null) {
            prettyAppendHeading(builder, "Supported Applications");
            for (ApplicationProtocol application : applications) {
                builder.append(application).append("\n");
            }
        }
    }

    private void appendDirectRaccoonResults(StringBuilder builder) {
        if (report.getRaccoonTestResultList() != null) {
            List<InformationLeakTest<?>> raccoonResults = new LinkedList<>();
            raccoonResults.addAll(report.getRaccoonTestResultList());
            appendInformationLeakTestList(builder, raccoonResults, "Direct Raccoon Results");
        }
    }

    public StringBuilder appendHsNormal(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Overview");
        prettyAppend(
                builder,
                "Tested Clients",
                Integer.toString(report.getSimulatedClientsResultList().size()));
        builder.append("\n");
        String identifier;
        identifier = "Handshakes - Successful";
        if (report.getHandshakeSuccessfulCounter() == 0) {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeSuccessfulCounter()),
                    AnsiColor.RED);
        } else {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeSuccessfulCounter()),
                    AnsiColor.GREEN);
        }
        identifier = "Handshakes - Failed";
        if (report.getHandshakeFailedCounter() == 0) {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeFailedCounter()),
                    AnsiColor.GREEN);
        } else {
            prettyAppend(
                    builder,
                    identifier,
                    Integer.toString(report.getHandshakeFailedCounter()),
                    AnsiColor.RED);
        }
        builder.append("\n");
        return builder;
    }

    public StringBuilder appendHandshakeSimulationTableRowHeading(
            StringBuilder builder,
            String tlsClient,
            String tlsVersion,
            String cipherSuite,
            String forwardSecrecy,
            String keyLength) {
        builder.append(String.format(hsClientFormat, tlsClient));
        builder.append(String.format("| " + hsVersionFormat, tlsVersion));
        builder.append(String.format("| " + hsCipherSuiteFormat, cipherSuite));
        builder.append(String.format("| " + hsForwardSecrecyFormat, forwardSecrecy));
        builder.append(String.format("| " + hsKeyLengthFormat, keyLength));
        builder.append("\n");
        return builder;
    }

    public StringBuilder appendHandshakeTableRowSuccessful(
            StringBuilder builder, SimulatedClientResult simulatedClient) {
        String clientName =
                simulatedClient.getTlsClientConfig().getType()
                        + ":"
                        + simulatedClient.getTlsClientConfig().getVersion();
        builder.append(
                getClientColor(
                        clientName,
                        simulatedClient.getConnectionInsecure(),
                        simulatedClient.getConnectionRfc7918Secure()));
        builder.append("| ")
                .append(
                        getProtocolVersionColor(
                                simulatedClient.getSelectedProtocolVersion(), hsVersionFormat));
        builder.append("| ")
                .append(
                        getCipherSuiteColor(
                                simulatedClient.getSelectedCipherSuite(), hsCipherSuiteFormat));
        builder.append("| ").append(getForwardSecrecyColor(simulatedClient.getForwardSecrecy()));
        builder.append("| ").append(getServerPublicKeyParameterColor(simulatedClient));
        builder.append("\n");
        return builder;
    }

    private String getClientColor(String tlsClient, Boolean insecure, Boolean rfc7918Secure) {
        if (tlsClient != null) {
            if (insecure != null && insecure) {
                return getRedString(tlsClient, hsClientFormat);
            } else if (rfc7918Secure != null && rfc7918Secure) {
                return getGreenString(tlsClient, hsClientFormat);
            }
        } else {
            return "Unknown";
        }
        return getBlackString(tlsClient, hsClientFormat);
    }

    private String getProtocolVersionColor(ProtocolVersion version, String format) {
        if (version != null) {
            if (version.name().contains("13") || version.name().contains("12")) {
                return getGreenString(version.name(), format);
            } else if (version.name().contains("11") || version.name().contains("10")) {
                return getYellowString(version.name(), format);
            } else if (version.name().contains("SSL")) {
                return getRedString(version.name(), format);
            } else {
                return getBlackString(version.name(), format);
            }
        } else {
            return "Unknown";
        }
    }

    private String getCipherSuiteColor(CipherSuite suite, String format) {
        if (suite != null) {
            CipherSuiteGrade grade = CipherSuiteRater.getGrade(suite);
            switch (grade) {
                case GOOD:
                    return getGreenString(suite.name(), format);
                case LOW:
                    return getRedString(suite.name(), format);
                case MEDIUM:
                    return getYellowString(suite.name(), format);
                case NONE:
                    return getBlackString(suite.name(), format);
                default:
                    return getBlackString(suite.name(), format);
            }
        } else {
            return "Unknown";
        }
    }

    private String getForwardSecrecyColor(Boolean forwardSecrecy) {
        String fs;
        if (forwardSecrecy != null) {
            if (forwardSecrecy) {
                fs = getGreenString("Forward Secrecy", hsForwardSecrecyFormat);
            } else {
                fs = getRedString("No Forward Secrecy", hsForwardSecrecyFormat);
            }
        } else {
            fs = "Unknown";
        }
        return fs;
    }

    private String getServerPublicKeyParameterColor(SimulatedClientResult simulatedClient) {
        String pubKeyParam = getServerPublicKeyParameterToPrint(simulatedClient);
        if (simulatedClient.getServerPublicKeyParameter() != null) {
            if (simulatedClient.getInsecureReasons() != null) {
                for (String reason : simulatedClient.getInsecureReasons()) {
                    if (reason.contains(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason())) {
                        return getRedString(pubKeyParam, "%s");
                    }
                }
            }
            return getGreenString(pubKeyParam, "%s");
        }
        return getBlackString(pubKeyParam, "%s");
    }

    private String getServerPublicKeyParameterToPrint(SimulatedClientResult simulatedClient) {
        CipherSuite suite = simulatedClient.getSelectedCipherSuite();
        Integer param = simulatedClient.getServerPublicKeyParameter();
        if (suite != null && param != null) {
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeRsa()) {
                return param + " bit - RSA";
            } else if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeDh()) {
                return param + " bit - DH";
            } else if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isKeyExchangeEcdh()) {
                return param + " bit - ECDH - " + simulatedClient.getSelectedNamedGroup();
            }
        }
        return null;
    }

    public StringBuilder appendHandshakeSimulationDetails(StringBuilder builder) {
        prettyAppendHeading(builder, "Handshake Simulation - Details");
        for (SimulatedClientResult simulatedClient : report.getSimulatedClientsResultList()) {
            prettyAppendHeading(
                    builder,
                    simulatedClient.getTlsClientConfig().getType()
                            + ":"
                            + simulatedClient.getTlsClientConfig().getVersion());

            prettyAppend(
                    builder,
                    "Handshake Successful",
                    "" + simulatedClient.getHandshakeSuccessful(),
                    simulatedClient.getHandshakeSuccessful() ? AnsiColor.GREEN : AnsiColor.RED);
            if (!simulatedClient.getHandshakeSuccessful()) {
                for (HandshakeFailureReasons failureReason : simulatedClient.getFailReasons()) {
                    prettyAppend(builder, "", getRedString(failureReason.getReason(), "%s"));
                }
            }
            builder.append("\n");
            if (simulatedClient.getConnectionInsecure() != null
                    && simulatedClient.getConnectionInsecure()) {
                prettyAppend(
                        builder,
                        "Connection Insecure",
                        simulatedClient.getConnectionInsecure(),
                        simulatedClient.getConnectionInsecure() ? AnsiColor.RED : AnsiColor.GREEN);
                for (String reason : simulatedClient.getInsecureReasons()) {
                    prettyAppend(builder, "", reason);
                }
            }
            prettyAppend(
                    builder,
                    "Connection Secure (RFC 7918)",
                    simulatedClient.getConnectionRfc7918Secure(),
                    simulatedClient.getConnectionRfc7918Secure()
                            ? AnsiColor.GREEN
                            : AnsiColor.DEFAULT_COLOR);

            builder.append("\n");
            prettyAppend(
                    builder,
                    "Protocol Version Selected",
                    getProtocolVersionColor(simulatedClient.getSelectedProtocolVersion(), "%s"));
            prettyAppend(
                    builder,
                    "Protocol Versions Client",
                    simulatedClient.getSupportedVersionList().toString());
            prettyAppend(
                    builder,
                    "Protocol Versions Server",
                    report.getSupportedProtocolVersions().toString());
            prettyAppend(
                    builder,
                    "Protocol Version is highest",
                    simulatedClient.getHighestPossibleProtocolVersionSelected(),
                    simulatedClient.getHighestPossibleProtocolVersionSelected()
                            ? AnsiColor.GREEN
                            : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(
                    builder,
                    "Selected CipherSuite",
                    getCipherSuiteColor(simulatedClient.getSelectedCipherSuite(), "%s"));
            prettyAppend(
                    builder,
                    "Forward Secrecy",
                    simulatedClient.getForwardSecrecy(),
                    simulatedClient.getForwardSecrecy() ? AnsiColor.GREEN : AnsiColor.RED);
            builder.append("\n");
            prettyAppend(
                    builder,
                    "Server Public Key",
                    getServerPublicKeyParameterColor(simulatedClient));
            builder.append("\n");
            if (simulatedClient.getSelectedCompressionMethod() != null) {
                prettyAppend(
                        builder,
                        "Selected Compression Method",
                        simulatedClient.getSelectedCompressionMethod().toString());
            } else {
                String tmp = null;
                prettyAppend(builder, "Selected Compression Method", tmp);
            }
            prettyAppend(
                    builder, "Negotiated Extensions", simulatedClient.getNegotiatedExtensions());
            // prettyAppend(builder, "Alpn Protocols", simulatedClient.getAlpnAnnouncedProtocols());
        }
        return builder;
    }

    public StringBuilder appendRfc(StringBuilder builder) {
        prettyAppendHeading(builder, "RFC (Experimental)");
        prettyAppend(
                builder,
                "Checks MAC (AppData)",
                report.getMacCheckPatternAppData().getType().name());
        prettyAppend(
                builder,
                "Checks MAC (Finished)",
                report.getMacCheckPatternFinished().getType().name());
        prettyAppend(builder, "Checks VerifyData", report.getVerifyCheckPattern().getType().name());
        return builder;
    }

    public StringBuilder appendRenegotiation(StringBuilder builder) {
        prettyAppendHeading(builder, "Renegotioation");
        prettyAppend(
                builder,
                "Secure (Extension)",
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION);
        prettyAppend(
                builder,
                "Secure (CipherSuite)",
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE);
        prettyAppend(
                builder,
                "Insecure",
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION);
        if (report.getProtocolType() == ProtocolType.DTLS) {
            prettyAppend(
                    builder,
                    "DTLS cookie exchange in renegotiation",
                    TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_RENEGOTIATION);
        }
        return builder;
    }

    public StringBuilder appendCertificates(StringBuilder builder) {
        int certCtr = 1;
        if (report.getCertificateChainList() != null
                && !report.getCertificateChainList().isEmpty()) {
            for (CertificateChain chain : report.getCertificateChainList()) {
                prettyAppendHeading(
                        builder,
                        "Certificate Chain (Certificate "
                                + certCtr
                                + " of "
                                + report.getCertificateChainList().size()
                                + ")");
                appendCertificate(builder, chain);
                certCtr++;
            }
        }
        return builder;
    }

    private StringBuilder appendCertificate(StringBuilder builder, CertificateChain chain) {
        prettyAppend(
                builder,
                "Chain ordered",
                chain.getChainIsOrdered(),
                chain.getChainIsOrdered() ? AnsiColor.GREEN : AnsiColor.YELLOW);
        prettyAppend(
                builder,
                "Contains Trust Anchor",
                chain.getContainsTrustAnchor(),
                chain.getContainsTrustAnchor() ? AnsiColor.RED : AnsiColor.GREEN);
        prettyAppend(
                builder,
                "Generally Trusted",
                chain.getGenerallyTrusted(),
                chain.getGenerallyTrusted() ? AnsiColor.GREEN : AnsiColor.RED);
        if (TrustAnchorManager.getInstance().hasCustomTrustAnchros()) {
            prettyAppend(
                    builder,
                    "Custom Trusted",
                    chain.getContainsCustomTrustAnchor(),
                    chain.getContainsCustomTrustAnchor() ? AnsiColor.GREEN : AnsiColor.RED);
        }
        if (chain.getCertificateIssues().size() > 0) {
            prettyAppendSubheading(builder, "Certificate Issues");
            for (CertificateIssue issue : chain.getCertificateIssues()) {
                prettyAppend(builder, issue.getHumanReadable(), AnsiColor.RED);
            }
        }
        if (!chain.getCertificateReportList().isEmpty()) {
            for (int i = 0; i < chain.getCertificateReportList().size(); i++) {
                CertificateReport certReport = chain.getCertificateReportList().get(i);
                prettyAppendSubheading(builder, "Certificate #" + (i + 1));

                if (certReport.getSubject() != null) {
                    prettyAppend(builder, "Subject", certReport.getSubject());
                }

                if (certReport.getIssuer() != null) {
                    prettyAppend(builder, "Issuer", certReport.getIssuer());
                }
                if (certReport.getValidFrom() != null) {
                    if (certReport.getValidFrom().before(new Date())) {
                        prettyAppend(
                                builder,
                                "Valid From",
                                certReport.getValidFrom().toString(),
                                AnsiColor.GREEN);
                    } else {
                        prettyAppend(
                                builder,
                                "Valid From",
                                certReport.getValidFrom().toString() + " - NOT YET VALID",
                                AnsiColor.RED);
                    }
                }
                if (certReport.getValidTo() != null) {
                    if (certReport.getValidTo().after(new Date())) {
                        prettyAppend(
                                builder,
                                "Valid Till",
                                certReport.getValidTo().toString(),
                                AnsiColor.GREEN);
                    } else {
                        prettyAppend(
                                builder,
                                "Valid Till",
                                certReport.getValidTo().toString() + " - EXPIRED",
                                AnsiColor.RED);
                    }
                }
                if (certReport.getValidFrom() != null
                        && certReport.getValidTo() != null
                        && certReport.getValidTo().after(new Date())) {
                    long time = certReport.getValidTo().getTime() - System.currentTimeMillis();
                    long days = TimeUnit.MILLISECONDS.toDays(time);
                    if (days < 1) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                "<1 day! This certificate expires very soon",
                                AnsiColor.RED);
                    } else if (days < 3) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                days + " days! This certificate expires soon",
                                AnsiColor.RED);
                    } else if (days < 14) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                days + " days. This certificate expires soon",
                                AnsiColor.YELLOW);
                    } else if (days < 31) {
                        prettyAppend(
                                builder, "Expires in", days + " days.", AnsiColor.DEFAULT_COLOR);
                    } else if (days < 730) {
                        prettyAppend(builder, "Expires in", days + " days.", AnsiColor.GREEN);
                    } else if (Objects.equals(certReport.getLeafCertificate(), Boolean.TRUE)) {
                        prettyAppend(
                                builder,
                                "Expires in",
                                days + " days. This is usually too long for a leaf certificate",
                                AnsiColor.RED);
                    } else {
                        prettyAppend(builder, "Expires in", days / 365 + " years", AnsiColor.GREEN);
                    }
                }
                if (certReport.getPublicKey() != null) {
                    prettyAppendPublicKey(builder, certReport.getPublicKey());
                }
                if (certReport.getWeakDebianKey() != null) {
                    prettyAppend(
                            builder,
                            "Weak Debian Key",
                            certReport.getWeakDebianKey(),
                            certReport.getWeakDebianKey() ? AnsiColor.RED : AnsiColor.GREEN);
                }
                if (certReport.getSignatureAndHashAlgorithm() != null) {
                    prettyAppend(
                            builder,
                            "Signature Algorithm",
                            certReport
                                    .getSignatureAndHashAlgorithm()
                                    .getSignatureAlgorithm()
                                    .name());
                }
                if (certReport.getSignatureAndHashAlgorithm() != null) {
                    if (certReport.getSignatureAndHashAlgorithm().getHashAlgorithm()
                                    == HashAlgorithm.SHA1
                            || certReport.getSignatureAndHashAlgorithm().getHashAlgorithm()
                                    == HashAlgorithm.MD5) {
                        if (!certReport.isTrustAnchor() && !certReport.getSelfSigned()) {
                            prettyAppend(
                                    builder,
                                    "Hash Algorithm",
                                    certReport
                                            .getSignatureAndHashAlgorithm()
                                            .getHashAlgorithm()
                                            .name(),
                                    AnsiColor.RED);
                        } else {
                            prettyAppend(
                                    builder,
                                    "Hash Algorithm",
                                    certReport
                                                    .getSignatureAndHashAlgorithm()
                                                    .getHashAlgorithm()
                                                    .name()
                                            + " - Not critical");
                        }
                    } else {
                        prettyAppend(
                                builder,
                                "Hash Algorithm",
                                certReport.getSignatureAndHashAlgorithm().getHashAlgorithm().name(),
                                AnsiColor.GREEN);
                    }
                }
                if (certReport.getExtendedValidation() != null) {
                    prettyAppend(
                            builder,
                            "Extended Validation",
                            certReport.getExtendedValidation(),
                            certReport.getExtendedValidation()
                                    ? AnsiColor.GREEN
                                    : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getCertificateTransparency() != null) {
                    prettyAppend(
                            builder,
                            "Certificate Transparency",
                            certReport.getCertificateTransparency(),
                            certReport.getCertificateTransparency()
                                    ? AnsiColor.GREEN
                                    : AnsiColor.YELLOW);
                }

                if (certReport.getCrlSupported() != null) {
                    prettyAppend(
                            builder,
                            "CRL Supported",
                            certReport.getCrlSupported(),
                            certReport.getCrlSupported()
                                    ? AnsiColor.GREEN
                                    : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getOcspSupported() != null) {
                    prettyAppend(
                            builder,
                            "OCSP Supported",
                            certReport.getOcspSupported(),
                            certReport.getOcspSupported() ? AnsiColor.GREEN : AnsiColor.YELLOW);
                }
                if (certReport.getOcspMustStaple() != null) {
                    prettyAppend(builder, "OCSP must Staple", certReport.getOcspMustStaple());
                }
                if (certReport.getRevoked() != null) {
                    prettyAppend(
                            builder,
                            "RevocationStatus",
                            certReport.getRevoked(),
                            certReport.getRevoked() ? AnsiColor.RED : AnsiColor.GREEN);
                }
                if (certReport.getDnsCAA() != null) {
                    prettyAppend(
                            builder,
                            "DNS CCA",
                            certReport.getDnsCAA(),
                            certReport.getDnsCAA() ? AnsiColor.GREEN : AnsiColor.DEFAULT_COLOR);
                }
                if (certReport.getRocaVulnerable() != null) {
                    prettyAppend(
                            builder,
                            "ROCA (simple)",
                            certReport.getRocaVulnerable(),
                            certReport.getRocaVulnerable() ? AnsiColor.RED : AnsiColor.GREEN);
                } else {
                    builder.append("ROCA (simple): not tested");
                }
                prettyAppendHexString(
                        builder, "Fingerprint (SHA256)", certReport.getSHA256Fingerprint());
            }
        }
        return builder;
    }

    private String prettyAppendPublicKey(StringBuilder builder, PublicKey publicKey) {
        if (publicKey instanceof CustomDhPublicKey) {
            CustomDhPublicKey dhPublicKey = (CustomDhPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "Static Diffie Hellman");

            prettyAppendHexString(builder, "Modulus", dhPublicKey.getModulus().toString(16));
            prettyAppendHexString(builder, "Generator", dhPublicKey.getModulus().toString(16));
            prettyAppendHexString(builder, "Y", dhPublicKey.getY().toString(16));
        } else if (publicKey instanceof CustomDsaPublicKey) {
            CustomDsaPublicKey dsaPublicKey = (CustomDsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "DSA");
            prettyAppendHexString(builder, "Modulus", dsaPublicKey.getDsaP().toString(16));
            prettyAppendHexString(builder, "Generator", dsaPublicKey.getDsaG().toString(16));
            prettyAppendHexString(builder, "Q", dsaPublicKey.getDsaQ().toString(16));
            prettyAppendHexString(builder, "X", dsaPublicKey.getY().toString(16));
        } else if (publicKey instanceof CustomRsaPublicKey) {
            CustomRsaPublicKey rsaPublicKey = (CustomRsaPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "RSA");
            prettyAppendHexString(builder, "Modulus", rsaPublicKey.getModulus().toString(16));
            prettyAppendHexString(
                    builder, "Public exponent", rsaPublicKey.getPublicExponent().toString(16));
        } else if (publicKey instanceof CustomEcPublicKey) {
            CustomEcPublicKey ecPublicKey = (CustomEcPublicKey) publicKey;
            prettyAppend(builder, "PublicKey Type:", "EC");
            if (ecPublicKey.getGroup() == null) {
                prettyAppend(builder, "Group (GOST)", ecPublicKey.getGostCurve().name());
            } else {
                prettyAppend(builder, "Group", ecPublicKey.getGroup().name());
            }
            prettyAppendHexString(builder, "Public Point", ecPublicKey.getPoint().toString(16));
        } else {
            builder.append(publicKey.toString()).append("\n");
        }
        return builder.toString();
    }

    private StringBuilder appendOcsp(StringBuilder builder) {
        prettyAppendHeading(builder, "OCSP");
        appendOcspOverview(builder);
        @SuppressWarnings("unchecked")
        ListResult<OcspCertificateResult> ocspResult =
                (ListResult<OcspCertificateResult>)
                        report.getListResult(TlsAnalyzedProperty.OCSP_RESULTS);
        if (ocspResult != null) {
            int certCtr = 1;
            for (OcspCertificateResult result : report.getOcspResults()) {
                prettyAppendSubheading(
                        builder,
                        "Detailed OCSP results for certificate "
                                + certCtr
                                + " of "
                                + report.getOcspResults().size());
                appendOcspForCertificate(builder, result);
                certCtr++;
            }
        }
        return builder;
    }

    private StringBuilder appendOcspOverview(StringBuilder builder) {
        prettyAppend(builder, "Supports OCSP ", TlsAnalyzedProperty.SUPPORTS_OCSP);
        // In case extension probe & OCSP probe differ, report stapling as
        // unreliable.
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST)
                        == TestResults.TRUE
                && report.getResult(TlsAnalyzedProperty.SUPPORTS_OCSP_STAPLING)
                        == TestResults.FALSE) {
            prettyAppend(builder, "OCSP Stapling is unreliable on this server.", AnsiColor.YELLOW);
            prettyAppend(
                    builder,
                    "Extension scan reported OCSP Stapling support, but OCSP scan does not.",
                    AnsiColor.YELLOW);
            prettyAppend(
                    builder,
                    "The results are likely incomplete. Maybe rescan for more information? \n",
                    AnsiColor.RED);
            report.putResult(TlsAnalyzedProperty.STAPLING_UNRELIABLE, TestResults.TRUE);
        } else if (report.getResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST)
                        == TestResults.FALSE
                && report.getResult(TlsAnalyzedProperty.SUPPORTS_OCSP_STAPLING)
                        == TestResults.TRUE) {
            prettyAppend(builder, "OCSP Stapling is unreliable on this server.", AnsiColor.YELLOW);
            prettyAppend(
                    builder,
                    "Extension scan reported no OCSP support, but OCSP scan does. \n",
                    AnsiColor.YELLOW);
            report.putResult(TlsAnalyzedProperty.STAPLING_UNRELIABLE, TestResults.TRUE);
        }

        // Print stapling support & 'must-staple'
        if (report.getResult(TlsAnalyzedProperty.STAPLING_UNRELIABLE) == TestResults.TRUE) {
            prettyAppend(builder, "OCSP Stapling", "true, but unreliable", AnsiColor.YELLOW);
            if (report.getResult(TlsAnalyzedProperty.MUST_STAPLE) == TestResults.TRUE) {
                prettyAppend(builder, "Must Staple", "true", AnsiColor.RED);
            } else {
                prettyAppend(builder, "Must Staple", TlsAnalyzedProperty.MUST_STAPLE);
            }
        } else {
            if (report.getResult(TlsAnalyzedProperty.MUST_STAPLE) == TestResults.TRUE) {
                if (report.getResult(TlsAnalyzedProperty.SUPPORTS_OCSP_STAPLING)
                        == TestResults.TRUE) {
                    prettyAppend(builder, "OCSP Stapling", "true", AnsiColor.GREEN);
                } else {
                    prettyAppend(builder, "OCSP Stapling", "false", AnsiColor.RED);
                }
                prettyAppend(builder, "Must Staple", "true", AnsiColor.GREEN);
            } else {
                prettyAppend(builder, "OCSP Stapling", TlsAnalyzedProperty.SUPPORTS_OCSP_STAPLING);
                prettyAppend(builder, "Must Staple", TlsAnalyzedProperty.MUST_STAPLE);
            }
        }

        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13)
                != TestResults.COULD_NOT_TEST) {
            prettyAppend(
                    builder,
                    "OCSP Stapling (TLS 1.3)",
                    TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13);
            prettyAppend(
                    builder,
                    "Multi Stapling (TLS 1.3)",
                    TlsAnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES);
        }
        if (Boolean.TRUE.equals(
                report.getResult(TlsAnalyzedProperty.SUPPORTS_NONCE) == TestResults.TRUE)) {
            prettyAppend(
                    builder, "Nonce Mismatch / Cached Nonce", TlsAnalyzedProperty.NONCE_MISMATCH);
        }

        // Is stapling supported, but a CertificateStatus message is missing?
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_OCSP_STAPLING) == TestResults.TRUE) {
            prettyAppend(
                    builder,
                    "Includes Stapled Response",
                    TlsAnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE);
            prettyAppend(
                    builder,
                    "Stapled Response Expired",
                    TlsAnalyzedProperty.STAPLED_RESPONSE_EXPIRED);
        }

        // Are nonces used? If so, do they match?
        prettyAppend(builder, "Supports Nonce", TlsAnalyzedProperty.SUPPORTS_NONCE);
        if (Boolean.TRUE.equals(
                report.getResult(TlsAnalyzedProperty.SUPPORTS_NONCE) == TestResults.TRUE)) {
            prettyAppend(
                    builder, "Nonce Mismatch / Cached Nonce", TlsAnalyzedProperty.NONCE_MISMATCH);
        }

        return builder;
    }

    private StringBuilder appendOcspForCertificate(
            StringBuilder builder, OcspCertificateResult result) {
        if (result.isSupportsStapling()) {
            if (result.getStapledResponse() != null) {
                prettyAppend(builder, "Includes Stapled Response", true);
                if (result.getFirstResponse().getResponseStatus() == 0) {
                    long differenceHoursStapled = result.getDifferenceHoursStapled();
                    if (differenceHoursStapled < 24) {
                        prettyAppend(
                                builder,
                                "Stapled Response Cached",
                                differenceHoursStapled + " hours",
                                AnsiColor.GREEN);
                    } else {
                        prettyAppend(
                                builder,
                                "Stapled Response Cached",
                                differenceHoursStapled / 24 + " days",
                                AnsiColor.YELLOW);
                    }
                    prettyAppend(
                            builder, "Stapled Response Expired", result.isStapledResponseExpired());
                }
                prettyAppend(builder, "Supports Stapled Nonce", result.isSupportsStapledNonce());
            } else {
                prettyAppend(builder, "Includes Stapled Response", false);
            }
        }

        prettyAppend(builder, "Supports Nonce", result.isSupportsNonce());
        prettyAppend(builder, "Nonce Mismatch / Cached Nonce", result.isNonceMismatch());

        if (result.getStapledResponse() != null) {
            prettyAppendSubheading(builder, "Stapled OCSP Response");
            if (result.getStapledResponse().getResponseStatus() > 0) {
                prettyAppend(
                        builder, "Server stapled an erroneous OCSP response. \n", AnsiColor.RED);
            }
            prettyAppend(builder, result.getStapledResponse().toString(false));
        }

        if (result.getFirstResponse() != null) {
            prettyAppendSubheading(builder, "Requested OCSP Response (HTTP POST)");
            if (result.getFirstResponse().getResponseStatus() > 0) {
                prettyAppend(
                        builder,
                        "OCSP Request was not accepted by the OCSP Responder.",
                        AnsiColor.RED);

                // Check if certificate chain was unordered. This will make the
                // request fail very likely.
                CertificateChain chain = result.getCertificate();
                if (Boolean.FALSE.equals(chain.getChainIsOrdered())) {
                    prettyAppend(
                            builder,
                            "This likely happened due the certificate chain being unordered. This is not supported yet by this scan.",
                            AnsiColor.RED);
                }
                prettyAppend(builder, result.getFirstResponse().toString(false));
            }
        } else if (result.getFirstResponse() == null && result.getHttpGetResponse() != null) {
            prettyAppend(
                    builder,
                    "Retrieved an OCSP response via HTTP GET, but not via HTTP POST.",
                    AnsiColor.YELLOW);
        }

        // Print requested HTTP GET response
        if (result.getHttpGetResponse() != null) {
            prettyAppendSubheading(builder, "Requested OCSP Response (HTTP GET)");
            prettyAppend(builder, result.getHttpGetResponse().toString(false));
        } else if (result.getHttpGetResponse() == null && result.getFirstResponse() != null) {
            prettyAppend(
                    builder,
                    "Retrieved an OCSP response via HTTP POST, but not via HTTP GET.",
                    AnsiColor.YELLOW);
        }

        return builder;
    }

    private StringBuilder appendCertificateTransparency(StringBuilder builder) {
        prettyAppendHeading(builder, "Certificate Transparency");
        prettyAppend(
                builder,
                "Supports Precertificate SCTs",
                TlsAnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE);
        prettyAppend(
                builder,
                "Supports TLS Handshake SCTs",
                TlsAnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE);
        prettyAppend(
                builder, "Supports OCSP Response SCTs", TlsAnalyzedProperty.SUPPORTS_SCTS_OCSP);
        prettyAppend(
                builder, "Meets Chrome's CT Policy", TlsAnalyzedProperty.SUPPORTS_CHROME_CT_POLICY);

        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE)
                == TestResults.TRUE) {
            prettyAppendSubheading(builder, "Precertificate SCTs");
            for (SignedCertificateTimestamp sct :
                    report.getPrecertificateSctList().getCertificateTimestampList()) {
                prettyAppend(builder, sct.toString() + "\n");
            }
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE) == TestResults.TRUE) {
            prettyAppendSubheading(builder, "TLS Handshake SCTs");
            for (SignedCertificateTimestamp sct :
                    report.getHandshakeSctList().getCertificateTimestampList()) {
                prettyAppend(builder, sct.toString() + "\n");
            }
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_SCTS_OCSP) == TestResults.TRUE) {
            prettyAppendSubheading(builder, "OCSP Response SCTs");
            for (SignedCertificateTimestamp sct :
                    report.getOcspSctList().getCertificateTimestampList()) {
                prettyAppend(builder, sct.toString() + "\n");
            }
        }

        return builder;
    }

    public StringBuilder appendSession(StringBuilder builder) {
        prettyAppendHeading(builder, "Session");
        prettyAppend(
                builder,
                "Supports Session ID Resumption",
                TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION);
        if (report.getProtocolType() == ProtocolType.DTLS) {
            prettyAppend(
                    builder,
                    "DTLS cookie exchange in Session ID Resumption",
                    TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION);
        }
        prettyAppend(
                builder, "Issues Session Tickets", TlsAnalyzedProperty.SUPPORTS_SESSION_TICKETS);
        prettyAppend(
                builder,
                "Supports Session Ticket Resumption",
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION);
        if (report.getProtocolType() == ProtocolType.DTLS) {
            prettyAppend(
                    builder,
                    "DTLS cookie exchange in Session Ticket Resumption",
                    TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION);
        }
        prettyAppend(
                builder,
                "Issues TLS 1.3 Session Tickets",
                TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS);
        prettyAppend(builder, "Supports TLS 1.3 PSK", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK);
        prettyAppend(
                builder, "Supports TLS 1.3 PSK-DHE", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);
        prettyAppend(builder, "Supports 0-RTT", TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT);
        // prettyAppend(builder, "Session Ticket Hint",
        // report.getSessionTicketLengthHint());
        // prettyAppendYellowOnFailure(builder, "Session Ticket Rotation",
        // report.getSessionTicketGetsRotated());
        // prettyAppendRedOnFailure(builder, "Ticketbleed",
        // report.getVulnerableTicketBleed());
        return builder;
    }

    public StringBuilder appendGcm(StringBuilder builder) {
        prettyAppendHeading(builder, "GCM");
        prettyAppend(builder, "GCM Nonce reuse", TlsAnalyzedProperty.REUSES_GCM_NONCES);
        if (null == report.getGcmPattern()) {
            prettyAppend(builder, "GCM Pattern", (String) null);
        } else {
            switch (report.getGcmPattern()) {
                case AWKWARD:
                    prettyAppend(
                            builder,
                            "GCM Pattern",
                            report.getGcmPattern().name(),
                            AnsiColor.YELLOW);
                    break;
                case INCREMENTING:
                case RANDOM:
                    prettyAppend(
                            builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.GREEN);
                    break;
                case REPEATING:
                    prettyAppend(
                            builder, "GCM Pattern", report.getGcmPattern().name(), AnsiColor.RED);
                    break;
                default:
                    prettyAppend(
                            builder,
                            "GCM Pattern",
                            report.getGcmPattern().name(),
                            AnsiColor.DEFAULT_COLOR);
                    break;
            }
        }
        prettyAppend(builder, "GCM Check", TlsAnalyzedProperty.MISSES_GCM_CHECKS);
        return builder;
    }

    public StringBuilder appendRecordFragmentation(StringBuilder builder) {
        prettyAppendHeading(builder, "Record Fragmentation");
        prettyAppend(
                builder,
                "Supports Record Fragmentation",
                TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION);
        return builder;
    }

    public StringBuilder appendIntolerances(StringBuilder builder) {
        prettyAppendHeading(builder, "Common Bugs [EXPERIMENTAL]");
        prettyAppend(builder, "Version Intolerant", TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE);
        prettyAppend(
                builder,
                "CipherSuite Intolerant",
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE);
        prettyAppend(
                builder, "Extension Intolerant", TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE);
        prettyAppend(
                builder,
                "CS Length Intolerant (>512 Byte)",
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE);
        prettyAppend(
                builder, "Compression Intolerant", TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE);
        prettyAppend(builder, "ALPN Intolerant", TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE);
        prettyAppend(
                builder,
                "CH Length Intolerant",
                TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE);
        prettyAppend(
                builder, "NamedGroup Intolerant", TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE);
        prettyAppend(
                builder,
                "Empty last Extension Intolerant",
                TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE);
        prettyAppend(
                builder,
                "SigHashAlgo Intolerant",
                TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE);
        prettyAppend(
                builder,
                "Big ClientHello Intolerant",
                TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE);
        prettyAppend(
                builder,
                "2nd CipherSuite Byte Bug",
                TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG);
        prettyAppend(
                builder,
                "Ignores offered Cipher suites",
                TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES);
        prettyAppend(
                builder,
                "Reflects offered Cipher suites",
                TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES);
        prettyAppend(
                builder,
                "Ignores offered NamedGroups",
                TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS);
        prettyAppend(
                builder,
                "Ignores offered SigHashAlgos",
                TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS);
        prettyAppend(
                builder,
                "Grease CipherSuite Intolerant",
                TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE);
        prettyAppend(
                builder,
                "Grease NamedGroup Intolerant",
                TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE);
        prettyAppend(
                builder,
                "Grease SigHashAlgo Intolerant",
                TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE);
        return builder;
    }

    public StringBuilder appendHelloRetry(StringBuilder builder) {
        prettyAppendHeading(builder, "TLS 1.3 Hello Retry Request");
        prettyAppend(
                builder,
                "Sends Hello Retry Request",
                TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST);
        prettyAppend(builder, "Issues Cookie", TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY);
        return builder;
    }

    public StringBuilder appendAttackVulnerabilities(StringBuilder builder) {
        prettyAppendHeading(builder, "Attack Vulnerabilities");
        if (report.getKnownPaddingOracleVulnerability() == null) {
            prettyAppend(
                    builder, "Padding Oracle", TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE);
        } else {
            prettyAppend(
                    builder,
                    "Padding Oracle",
                    "true - " + report.getKnownPaddingOracleVulnerability().getShortName(),
                    AnsiColor.RED);
        }
        prettyAppend(builder, "Bleichenbacher", TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER);
        prettyAppend(builder, "Raccoon", TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK);
        prettyAppend(builder, "Direct Raccoon", TlsAnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON);
        prettyAppend(builder, "CRIME", TlsAnalyzedProperty.VULNERABLE_TO_CRIME);
        prettyAppend(builder, "Breach", TlsAnalyzedProperty.VULNERABLE_TO_BREACH);
        prettyAppend(builder, "Invalid Curve", TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE);
        prettyAppend(
                builder,
                "Invalid Curve (ephemeral)",
                TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL);
        prettyAppend(
                builder,
                "Invalid Curve (twist)",
                TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST);
        prettyAppend(builder, "SSL Poodle", TlsAnalyzedProperty.VULNERABLE_TO_POODLE);
        prettyAppend(builder, "Logjam", TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM);
        prettyAppend(builder, "Sweet 32", TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32);
        prettyAppend(builder, "General DROWN", TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN);
        prettyAppend(
                builder, "Extra Clear DROWN", TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN);
        prettyAppend(builder, "Heartbleed", TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
        prettyAppend(builder, "EarlyCcs", TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS);
        prettyAppend(
                builder,
                "CVE-2020-13777 (Zero key)",
                TlsAnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY);
        prettyAppend(builder, "ALPACA", TlsAnalyzedProperty.ALPACA_MITIGATED);
        prettyAppend(builder, "Renegotiation Attack (ext)");
        prettyAppend(
                builder,
                "-1.hs without ext, 2.hs with ext",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1);
        prettyAppend(
                builder,
                "-1.hs with ext, 2.hs without ext",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2);
        prettyAppend(builder, "Renegotiation Attack (cs)");
        prettyAppend(
                builder,
                "-1.hs without cs, 2.hs with cs",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1);
        prettyAppend(
                builder,
                "-1.hs with cs, 2.hs without cs",
                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2);
        return builder;
    }

    public StringBuilder appendRaccoonAttackDetails(StringBuilder builder) {
        DecimalFormat decimalFormat = new DecimalFormat();
        decimalFormat.setMaximumFractionDigits(24);
        if ((report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK) == TestResults.TRUE
                        || detail.isGreaterEqualTo(ScannerDetail.DETAILED))
                && report.getRaccoonAttackProbabilities() != null) {
            prettyAppendHeading(builder, "Raccoon Attack Details");
            prettyAppend(
                    builder,
                    "Here we are calculating how likely it is that the attack can reach a critical block border.");
            prettyAppend(
                    builder,
                    "Available Injection points:",
                    (long) report.getRaccoonAttackProbabilities().size());
            if (report.getRaccoonAttackProbabilities().size() > 0) {
                prettyAppendSubheading(builder, "Probabilities");
                prettyAppend(
                        builder,
                        addIndentations("InjectionPoint") + "\t Leak" + "\tProbability",
                        AnsiColor.BOLD);
                for (RaccoonAttackProbabilities probabilities :
                        report.getRaccoonAttackProbabilities()) {
                    builder.append(
                            addIndentations(probabilities.getPosition().name())
                                    + "\t "
                                    + probabilities.getBitsLeaked()
                                    + "\t"
                                    + decimalFormat.format(probabilities.getChanceForEquation())
                                    + "\n");
                }
                if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                        || report.getResult(TlsAnalyzedProperty.SUPPORTS_PSK_DHE)
                                == TestResults.TRUE) {
                    prettyAppendSubheading(builder, "PSK Length Probabilities");
                    prettyAppend(
                            builder,
                            addIndentations("PSK Length")
                                    + addIndentations("BitLeak")
                                    + "Probability",
                            AnsiColor.BOLD);

                    for (RaccoonAttackProbabilities probabilities :
                            report.getRaccoonAttackProbabilities()) {

                        prettyAppendSubheading(builder, probabilities.getPosition().name());

                        for (RaccoonAttackPskProbabilities pskProbability :
                                probabilities.getPskProbabilityList()) {
                            prettyAppend(
                                    builder,
                                    addIndentations("" + pskProbability.getPskLength())
                                            + addIndentations(
                                                    ""
                                                            + pskProbability
                                                                    .getZeroBitsRequiredToNextBlockBorder())
                                            + decimalFormat.format(
                                                    pskProbability.getChanceForEquation()));
                        }
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendInformationLeakTestList(
            StringBuilder builder,
            List<InformationLeakTest<?>> informationLeakTestList,
            String heading) {
        prettyAppendHeading(builder, heading);
        if (informationLeakTestList == null || informationLeakTestList.isEmpty()) {
            prettyAppend(builder, "No test results");
        } else {
            for (InformationLeakTest<?> testResult : informationLeakTestList) {
                String valueP;
                if (testResult.getValueP() >= 0.001) {
                    valueP = String.format("%.3f", testResult.getValueP());
                } else {
                    valueP = "<0.001";
                }
                String resultString = testResult.getTestInfo().getPrintableName();
                if (testResult.getValueP() < 0.01) {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength(testResult.getEqualityError().name(), 25)
                                    + padToLength("| VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.RED);
                } else if (testResult.getValueP() < 0.05) {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength(testResult.getEqualityError().name(), 25)
                                    + padToLength("| PROBABLY VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.YELLOW);
                } else if (testResult.getValueP() < 1) {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength("No significant difference", 25)
                                    + padToLength("| NOT VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.GREEN);
                } else {
                    prettyAppend(
                            builder,
                            padToLength(resultString, 80)
                                    + " | "
                                    + padToLength("No behavior difference", 25)
                                    + padToLength("| NOT VULNERABLE", 25)
                                    + "| P: "
                                    + valueP,
                            AnsiColor.GREEN);
                }

                if ((detail == ScannerDetail.DETAILED
                                && Objects.equals(
                                        testResult.isSignificantDistinctAnswers(), Boolean.TRUE))
                        || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE
                            || detail == ScannerDetail.ALL) {
                        prettyAppend(builder, "Response Map", AnsiColor.YELLOW);
                        appendInformationLeakTestResult(builder, testResult);
                    }
                }
            }
        }
        return builder;
    }

    public StringBuilder appendPaddingOracleResults(StringBuilder builder) {
        try {
            if (Objects.equals(
                    report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE),
                    TestResults.TRUE)) {
                prettyAppendHeading(builder, "PaddingOracle Details");

                if (report.getKnownPaddingOracleVulnerability() != null) {
                    KnownPaddingOracleVulnerability knownVulnerability =
                            report.getKnownPaddingOracleVulnerability();
                    prettyAppend(
                            builder,
                            "Identification",
                            knownVulnerability.getLongName(),
                            AnsiColor.RED);
                    prettyAppend(builder, "CVE", knownVulnerability.getCve(), AnsiColor.RED);
                    if (knownVulnerability.getStrength() != PaddingOracleStrength.WEAK) {
                        prettyAppend(
                                builder,
                                "Strength",
                                knownVulnerability.getStrength().name(),
                                AnsiColor.RED);
                    } else {
                        prettyAppend(
                                builder,
                                "Strength",
                                knownVulnerability.getStrength().name(),
                                AnsiColor.YELLOW);
                    }
                    if (knownVulnerability.isObservable()) {
                        prettyAppend(
                                builder,
                                "Observable",
                                "" + knownVulnerability.isObservable(),
                                AnsiColor.RED);
                    } else {
                        prettyAppend(
                                builder,
                                "Observable",
                                "" + knownVulnerability.isObservable(),
                                AnsiColor.YELLOW);
                    }
                    prettyAppend(builder, "\n");
                    prettyAppend(builder, knownVulnerability.getDescription());
                    prettyAppendHeading(builder, "Affected Products");

                    for (String s : knownVulnerability.getAffectedProducts()) {
                        prettyAppend(builder, s, AnsiColor.YELLOW);
                    }
                    prettyAppend(builder, "");
                    prettyAppend(
                            builder,
                            "If your tested software/hardware is not in this list, please let us know so we can add it here.");
                } else {
                    prettyAppend(
                            builder,
                            "Identification",
                            "Could not identify vulnerability. Please contact us if you know which software/hardware is generating this behavior.",
                            AnsiColor.YELLOW);
                }
            }
            prettyAppendHeading(builder, "PaddingOracle response map");
            if (report.getPaddingOracleTestResultList() == null
                    || report.getPaddingOracleTestResultList().isEmpty()) {
                prettyAppend(builder, "No test results");
            } else {
                prettyAppend(builder, "No vulnerability present to identify");

                // TODO this recopying is weird // this recopying is necessary to call
                // appendInformationLeakTestList,
                // otherwise there are problems with generic types
                List<InformationLeakTest<?>> informationLeakTestList = new LinkedList<>();
                informationLeakTestList.addAll(report.getPaddingOracleTestResultList());
                appendInformationLeakTestList(
                        builder, informationLeakTestList, "Padding Oracle Details");
            }
            prettyAppend(builder, "No test results");
        } catch (Exception e) {
            prettyAppend(builder, "Error:" + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendInformationLeakTestResult(
            StringBuilder builder, InformationLeakTest<?> informationLeakTest) {
        try {
            ResponseFingerprint defaultAnswer =
                    informationLeakTest.retrieveMostCommonAnswer().getFingerprint();
            List<VectorContainer> vectorContainerList =
                    informationLeakTest.getVectorContainerList();
            for (VectorContainer vectorContainer : vectorContainerList) {
                prettyAppend(
                        builder, "\t" + padToLength(vectorContainer.getVector().getName(), 40));
                for (ResponseCounter counter : vectorContainer.getDistinctResponsesCounterList()) {
                    AnsiColor color = AnsiColor.GREEN;
                    if (!counter.getFingerprint().equals(defaultAnswer)) {
                        // TODO received app data should also make this red
                        color = AnsiColor.RED;
                    }
                    prettyAppend(
                            builder,
                            "\t\t"
                                    + padToLength((counter.getFingerprint().toHumanReadable()), 40)
                                    + counter.getCounter()
                                    + "/"
                                    + counter.getTotal()
                                    + " ("
                                    + String.format("%.2f", counter.getProbability() * 100)
                                    + "%)",
                            color);
                }
            }
        } catch (Exception e) {
            prettyAppend(builder, "Error: " + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendBleichenbacherResults(StringBuilder builder) {
        try {
            prettyAppendHeading(builder, "Bleichenbacher response map");
            if (report.getBleichenbacherTestResultList() == null
                    || report.getBleichenbacherTestResultList().isEmpty()) {
                prettyAppend(builder, "No test results");
            } else {
                prettyAppend(builder, "No vulnerability present to identify");

                // TODO this recopying is weird
                List<InformationLeakTest<?>> informationLeakTestList = new LinkedList<>();
                informationLeakTestList.addAll(report.getBleichenbacherTestResultList());
                appendInformationLeakTestList(
                        builder, informationLeakTestList, "Bleichenbacher Details");
            }
            prettyAppend(builder, "No test results");
        } catch (Exception e) {
            prettyAppend(builder, "Error:" + e.getMessage());
        }
        return builder;
    }

    public StringBuilder appendEcPointFormats(StringBuilder builder) {
        prettyAppendHeading(builder, "Elliptic Curve Point Formats");
        prettyAppend(builder, "Uncompressed", TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT);
        prettyAppend(
                builder, "ANSIX962 Prime", TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME);
        prettyAppend(
                builder, "ANSIX962 Char2", TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2);
        prettyAppend(
                builder,
                "TLS 1.3 ANSIX962  SECP",
                TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION);
        return builder;
    }

    public StringBuilder appendInvalidCurveResults(StringBuilder builder) {
        prettyAppendHeading(builder, "Invalid Curve Details");
        boolean foundCouldNotTest = false;
        List<InvalidCurveResponse> invalidCurvesResults = report.getInvalidCurveTestResultList();
        if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE)
                        == TestResults.NOT_TESTED_YET
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL)
                        == TestResults.NOT_TESTED_YET
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST)
                        == TestResults.NOT_TESTED_YET) {
            prettyAppend(builder, "Not Tested");
        } else if (invalidCurvesResults == null) {
            prettyAppend(builder, "No test results");
        } else if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE)
                        == TestResults.FALSE
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL)
                        == TestResults.FALSE
                && report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST)
                        == TestResults.FALSE
                && detail != ScannerDetail.ALL) {
            prettyAppend(builder, "No Vulnerabilities found");
        } else {
            for (InvalidCurveResponse response : invalidCurvesResults) {
                if (response.getChosenGroupReusesKey() == TestResults.COULD_NOT_TEST
                        || response.getShowsVulnerability() == TestResults.COULD_NOT_TEST
                        || response.getShowsVulnerability() == TestResults.COULD_NOT_TEST) {
                    foundCouldNotTest = true;
                }
                if ((response.getShowsVulnerability() == TestResults.TRUE
                                && detail.isGreaterEqualTo(ScannerDetail.NORMAL))
                        || (response.getShowsPointsAreNotValidated() == TestResults.TRUE
                                && detail.isGreaterEqualTo(ScannerDetail.DETAILED))
                        || detail == ScannerDetail.ALL) {
                    prettyAppend(builder, response.getVector().toString());
                    switch ((TestResults) response.getShowsPointsAreNotValidated()) {
                        case TRUE:
                            prettyAppend(
                                    builder, "Server did not validate points", AnsiColor.YELLOW);
                            break;
                        case FALSE:
                            prettyAppend(
                                    builder,
                                    "Server did validate points / uses invulnerable algorithm",
                                    AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(
                                    builder, "Could not test point validation", AnsiColor.YELLOW);
                            break;
                    }
                    switch ((TestResults) response.getChosenGroupReusesKey()) {
                        case TRUE:
                            prettyAppend(builder, "Server did reuse key", AnsiColor.YELLOW);
                            break;
                        case FALSE:
                            prettyAppend(builder, "Server did not reuse key", AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(builder, "Could not test key reuse", AnsiColor.YELLOW);
                            break;
                    }
                    switch ((TestResults) response.getShowsVulnerability()) {
                        case TRUE:
                            prettyAppend(builder, "Server is vulnerable", AnsiColor.RED);
                            break;
                        case FALSE:
                            prettyAppend(builder, "Server is not vulnerable", AnsiColor.GREEN);
                            break;
                        default:
                            prettyAppend(
                                    builder, "Could not test for vulnerability", AnsiColor.YELLOW);
                            break;
                    }
                    switch ((TestResults) response.getSideChannelSuspected()) {
                        case TRUE:
                            prettyAppend(builder, "Side Channel suspected", AnsiColor.RED);
                            break;
                        default:
                            prettyAppend(builder, "No Side Channel suspected", AnsiColor.GREEN);
                            break;
                    }
                }
            }
        }

        if (foundCouldNotTest && detail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            prettyAppend(builder, "Some tests did not finish", AnsiColor.YELLOW);
        }
        return builder;
    }

    public String toHumanReadable(ProtocolVersion version) {
        switch (version) {
            case DTLS10:
                return "DTLS 1.0";
            case DTLS12:
                return "DTLS 1.2";
            case SSL2:
                return "SSL 2.0";
            case SSL3:
                return "SSL 3.0";
            case TLS10:
                return "TLS 1.0";
            case TLS11:
                return "TLS 1.1";
            case TLS12:
                return "TLS 1.2";
            case TLS13:
                return "TLS 1.3";
            case TLS13_DRAFT14:
                return "TLS 1.3 Draft-14";
            case TLS13_DRAFT15:
                return "TLS 1.3 Draft-15";
            case TLS13_DRAFT16:
                return "TLS 1.3 Draft-16";
            case TLS13_DRAFT17:
                return "TLS 1.3 Draft-17";
            case TLS13_DRAFT18:
                return "TLS 1.3 Draft-18";
            case TLS13_DRAFT19:
                return "TLS 1.3 Draft-19";
            case TLS13_DRAFT20:
                return "TLS 1.3 Draft-20";
            case TLS13_DRAFT21:
                return "TLS 1.3 Draft-21";
            case TLS13_DRAFT22:
                return "TLS 1.3 Draft-22";
            case TLS13_DRAFT23:
                return "TLS 1.3 Draft-23";
            case TLS13_DRAFT24:
                return "TLS 1.3 Draft-24";
            case TLS13_DRAFT25:
                return "TLS 1.3 Draft-25";
            case TLS13_DRAFT26:
                return "TLS 1.3 Draft-26";
            case TLS13_DRAFT27:
                return "TLS 1.3 Draft-27";
            case TLS13_DRAFT28:
                return "TLS 1.3 Draft-28";
            default:
                return version.name();
        }
    }

    public StringBuilder appendCipherSuites(StringBuilder builder) {
        Set<CipherSuite> ciphersuites = report.getSupportedCipherSuites();
        if (ciphersuites != null) {
            prettyAppendHeading(builder, "Supported Cipher suites");
            if (!ciphersuites.isEmpty()) {
                for (CipherSuite suite : ciphersuites) {
                    builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                }
            } else {
                prettyAppend(builder, "-empty-", AnsiColor.RED);
            }
            if (report.getVersionSuitePairs() != null && !report.getVersionSuitePairs().isEmpty()) {
                for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                    prettyAppendHeading(
                            builder,
                            "Supported in "
                                    + toHumanReadable(versionSuitePair.getVersion())
                                    + (report.getResult(TlsAnalyzedProperty.ENFORCES_CS_ORDERING)
                                                    == TestResults.TRUE
                                            ? "(server order)"
                                            : ""));
                    for (CipherSuite suite : versionSuitePair.getCipherSuiteList()) {
                        builder.append(getCipherSuiteColor(suite, "%s")).append("\n");
                    }
                }
            }

            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                prettyAppendHeading(builder, "Symmetric Supported");
                prettyAppend(builder, "Null", TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS);
                prettyAppend(builder, "Export", TlsAnalyzedProperty.SUPPORTS_EXPORT);
                prettyAppend(builder, "Anon", TlsAnalyzedProperty.SUPPORTS_ANON);
                prettyAppend(builder, "DES", TlsAnalyzedProperty.SUPPORTS_DES);
                prettyAppend(builder, "SEED", TlsAnalyzedProperty.SUPPORTS_SEED);
                prettyAppend(builder, "IDEA", TlsAnalyzedProperty.SUPPORTS_IDEA);
                prettyAppend(builder, "RC2", TlsAnalyzedProperty.SUPPORTS_RC2);
                prettyAppend(builder, "RC4", TlsAnalyzedProperty.SUPPORTS_RC4);
                prettyAppend(builder, "3DES", TlsAnalyzedProperty.SUPPORTS_3DES);
                prettyAppend(builder, "AES", TlsAnalyzedProperty.SUPPORTS_AES);
                prettyAppend(builder, "CAMELLIA", TlsAnalyzedProperty.SUPPORTS_CAMELLIA);
                prettyAppend(builder, "ARIA", TlsAnalyzedProperty.SUPPORTS_ARIA);
                prettyAppend(builder, "CHACHA20 POLY1305", TlsAnalyzedProperty.SUPPORTS_CHACHA);

                prettyAppendHeading(builder, "KeyExchange Supported");
                prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA);
                prettyAppend(builder, "STATIC-DH", TlsAnalyzedProperty.SUPPORTS_STATIC_DH);
                prettyAppend(builder, "DHE", TlsAnalyzedProperty.SUPPORTS_DHE);
                prettyAppend(builder, "ECDH", TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH);
                prettyAppend(builder, "ECDHE", TlsAnalyzedProperty.SUPPORTS_ECDHE);
                prettyAppend(builder, "GOST", TlsAnalyzedProperty.SUPPORTS_GOST);
                // prettyAppend(builder, "SRP", report.getSupportsSrp());
                prettyAppend(builder, "Kerberos", TlsAnalyzedProperty.SUPPORTS_KERBEROS);
                prettyAppend(builder, "Plain PSK", TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN);
                prettyAppend(builder, "PSK RSA", TlsAnalyzedProperty.SUPPORTS_PSK_RSA);
                prettyAppend(builder, "PSK DHE", TlsAnalyzedProperty.SUPPORTS_PSK_DHE);
                prettyAppend(builder, "PSK ECDHE", TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE);
                prettyAppend(builder, "Fortezza", TlsAnalyzedProperty.SUPPORTS_FORTEZZA);
                prettyAppend(builder, "New Hope", TlsAnalyzedProperty.SUPPORTS_NEWHOPE);
                prettyAppend(builder, "ECMQV", TlsAnalyzedProperty.SUPPORTS_ECMQV);
                prettyAppend(
                        builder, "TLS 1.3 PSK_DHE", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);

                prettyAppendHeading(builder, "KeyExchange Signatures");
                prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA_CERT);
                prettyAppend(builder, "ECDSA", TlsAnalyzedProperty.SUPPORTS_ECDSA);
                prettyAppend(builder, "DSS", TlsAnalyzedProperty.SUPPORTS_DSS);

                prettyAppendHeading(builder, "Cipher Types Supports");
                prettyAppend(builder, "Stream", TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS);
                prettyAppend(builder, "Block", TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
                prettyAppend(builder, "AEAD", TlsAnalyzedProperty.SUPPORTS_AEAD);
            }
            prettyAppendHeading(builder, "Perfect Forward Secrecy");
            prettyAppend(builder, "Supports PFS", TlsAnalyzedProperty.SUPPORTS_PFS);
            prettyAppend(builder, "Prefers PFS", TlsAnalyzedProperty.PREFERS_PFS);
            prettyAppend(builder, "Supports Only PFS", TlsAnalyzedProperty.SUPPORTS_ONLY_PFS);

            prettyAppendHeading(builder, "CipherSuite General");
            prettyAppend(
                    builder,
                    "Enforces CipherSuite ordering",
                    TlsAnalyzedProperty.ENFORCES_CS_ORDERING);
        }

        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppendHeading(builder, "Symmetric Supported");
            prettyAppend(builder, "Null", TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS);
            prettyAppend(builder, "Export", TlsAnalyzedProperty.SUPPORTS_EXPORT);
            prettyAppend(builder, "Anon", TlsAnalyzedProperty.SUPPORTS_ANON);
            prettyAppend(builder, "DES", TlsAnalyzedProperty.SUPPORTS_DES);
            prettyAppend(builder, "SEED", TlsAnalyzedProperty.SUPPORTS_SEED);
            prettyAppend(builder, "IDEA", TlsAnalyzedProperty.SUPPORTS_IDEA);
            prettyAppend(builder, "RC2", TlsAnalyzedProperty.SUPPORTS_RC2);
            prettyAppend(builder, "RC4", TlsAnalyzedProperty.SUPPORTS_RC4);
            prettyAppend(builder, "3DES", TlsAnalyzedProperty.SUPPORTS_3DES);
            prettyAppend(builder, "AES", TlsAnalyzedProperty.SUPPORTS_AES);
            prettyAppend(builder, "CAMELLIA", TlsAnalyzedProperty.SUPPORTS_CAMELLIA);
            prettyAppend(builder, "ARIA", TlsAnalyzedProperty.SUPPORTS_ARIA);
            prettyAppend(builder, "CHACHA20 POLY1305", TlsAnalyzedProperty.SUPPORTS_CHACHA);

            prettyAppendHeading(builder, "KeyExchange Supported");
            prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA);
            prettyAppend(builder, "STATIC-DH", TlsAnalyzedProperty.SUPPORTS_STATIC_DH);
            prettyAppend(builder, "DHE", TlsAnalyzedProperty.SUPPORTS_DHE);
            prettyAppend(builder, "ECDH", TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH);
            prettyAppend(builder, "ECDHE", TlsAnalyzedProperty.SUPPORTS_ECDHE);
            prettyAppend(builder, "GOST", TlsAnalyzedProperty.SUPPORTS_GOST);
            // prettyAppend(builder, "SRP", report.getSupportsSrp());
            prettyAppend(builder, "Kerberos", TlsAnalyzedProperty.SUPPORTS_KERBEROS);
            prettyAppend(builder, "Plain PSK", TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN);
            prettyAppend(builder, "PSK RSA", TlsAnalyzedProperty.SUPPORTS_PSK_RSA);
            prettyAppend(builder, "PSK DHE", TlsAnalyzedProperty.SUPPORTS_PSK_DHE);
            prettyAppend(builder, "PSK ECDHE", TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE);
            prettyAppend(builder, "Fortezza", TlsAnalyzedProperty.SUPPORTS_FORTEZZA);
            prettyAppend(builder, "New Hope", TlsAnalyzedProperty.SUPPORTS_NEWHOPE);
            prettyAppend(builder, "ECMQV", TlsAnalyzedProperty.SUPPORTS_ECMQV);
            prettyAppend(builder, "TLS 1.3 PSK_DHE", TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);

            prettyAppendHeading(builder, "KeyExchange Signatures");
            prettyAppend(builder, "RSA", TlsAnalyzedProperty.SUPPORTS_RSA_CERT);
            prettyAppend(builder, "ECDSA", TlsAnalyzedProperty.SUPPORTS_ECDSA);
            prettyAppend(builder, "DSS", TlsAnalyzedProperty.SUPPORTS_DSS);

            prettyAppendHeading(builder, "Cipher Types Supports");
            prettyAppend(builder, "Stream", TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS);
            prettyAppend(builder, "Block", TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
            prettyAppend(builder, "AEAD", TlsAnalyzedProperty.SUPPORTS_AEAD);
        }
        prettyAppendHeading(builder, "Perfect Forward Secrecy");
        prettyAppend(builder, "Supports PFS", TlsAnalyzedProperty.SUPPORTS_PFS);
        prettyAppend(builder, "Prefers PFS", TlsAnalyzedProperty.PREFERS_PFS);
        prettyAppend(builder, "Supports Only PFS", TlsAnalyzedProperty.SUPPORTS_ONLY_PFS);

        prettyAppendHeading(builder, "CipherSuite General");
        prettyAppend(
                builder, "Enforces CipherSuite ordering", TlsAnalyzedProperty.ENFORCES_CS_ORDERING);
        return builder;
    }

    public StringBuilder appendProtocolVersions(StringBuilder builder) {
        if (report.getSupportedProtocolVersions() != null) {
            prettyAppendHeading(builder, "Versions");
            prettyAppend(builder, "DTLS 1.0", TlsAnalyzedProperty.SUPPORTS_DTLS_1_0);
            prettyAppend(builder, "DTLS 1.2", TlsAnalyzedProperty.SUPPORTS_DTLS_1_2);
            prettyAppend(builder, "SSL 2.0", TlsAnalyzedProperty.SUPPORTS_SSL_2);
            prettyAppend(builder, "SSL 3.0", TlsAnalyzedProperty.SUPPORTS_SSL_3);
            prettyAppend(builder, "TLS 1.0", TlsAnalyzedProperty.SUPPORTS_TLS_1_0);
            prettyAppend(builder, "TLS 1.1", TlsAnalyzedProperty.SUPPORTS_TLS_1_1);
            prettyAppend(builder, "TLS 1.2", TlsAnalyzedProperty.SUPPORTS_TLS_1_2);
            prettyAppend(builder, "TLS 1.3", TlsAnalyzedProperty.SUPPORTS_TLS_1_3);
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 14", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 15", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 16", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 17", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 18", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 19", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 20", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 21", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 22", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 23", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 24", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 25", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 26", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 27", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27);
            }
            if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)
                    || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28)
                            == TestResults.TRUE) {
                prettyAppend(
                        builder, "TLS 1.3 Draft 28", TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28);
            }
        }
        return builder;
    }

    public StringBuilder appendHttps(StringBuilder builder) {
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE) {
            prettyAppendHeading(builder, "HSTS");
            try {

                if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HSTS) == TestResults.TRUE) {
                    prettyAppend(builder, "HSTS", TlsAnalyzedProperty.SUPPORTS_HSTS);
                    prettyAppend(
                            builder,
                            "HSTS Preloading",
                            TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING);
                    prettyAppend(builder, "max-age (seconds)", (long) report.getHstsMaxAge());
                } else {
                    prettyAppend(builder, "Not supported");
                }
                prettyAppendHeading(builder, "HPKP");
                if (report.getResult(TlsAnalyzedProperty.SUPPORTS_HPKP) == TestResults.TRUE
                        || report.getResult(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING)
                                == TestResults.TRUE) {
                    prettyAppend(builder, "HPKP", TlsAnalyzedProperty.SUPPORTS_HPKP);
                    prettyAppend(
                            builder,
                            "HPKP (report only)",
                            TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING);
                    prettyAppend(builder, "max-age (seconds)", (long) report.getHpkpMaxAge());

                    List<HpkpPin> normalPins = report.getNormalHpkpPins();
                    if (normalPins.size() > 0) {
                        prettyAppend(builder, "");
                        prettyAppend(builder, "HPKP-Pins:", AnsiColor.GREEN);
                        for (HpkpPin pin : normalPins) {
                            prettyAppend(builder, pin.toString());
                        }
                    }
                    List<HpkpPin> reportOnlyPins = report.getReportOnlyHpkpPins();
                    if (reportOnlyPins.size() > 0) {
                        prettyAppend(builder, "");
                        prettyAppend(builder, "Report Only HPKP-Pins:", AnsiColor.GREEN);
                        for (HpkpPin pin : reportOnlyPins) {
                            prettyAppend(builder, pin.toString());
                        }
                    }

                } else {
                    prettyAppend(builder, "Not supported");
                }
                prettyAppendHeading(builder, "HTTPS Response Header");
                for (HttpHeader header : report.getHttpHeader()) {
                    prettyAppend(
                            builder,
                            header.getHeaderName().getValue()
                                    + ":"
                                    + header.getHeaderValue().getValue());
                }
                prettyAppendHeading(builder, "HTTP False Start");
                prettyAppend(
                        builder, "HTTP False Start", TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START);
            } catch (Exception e) {
                prettyAppend(builder, "Error: " + e.getMessage());
            }
        }

        return builder;
    }

    public StringBuilder appendExtensions(StringBuilder builder) {
        List<ExtensionType> extensions = report.getSupportedExtensions();
        if (extensions != null) {
            prettyAppendHeading(builder, "Supported Extensions");
            for (ExtensionType type : extensions) {
                builder.append(type.name()).append("\n");
            }
        }
        prettyAppendHeading(builder, "Extensions");
        prettyAppend(
                builder,
                "Secure Renegotiation",
                TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION);
        prettyAppend(
                builder,
                "Extended Master Secret",
                TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET);
        prettyAppend(builder, "Encrypt Then Mac", TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC);
        prettyAppend(builder, "Tokenbinding", TlsAnalyzedProperty.SUPPORTS_TOKENBINDING);
        prettyAppend(
                builder,
                "Certificate Status Request",
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST);
        prettyAppend(
                builder,
                "Certificate Status Request v2",
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2);
        prettyAppend(builder, "ESNI", TlsAnalyzedProperty.SUPPORTS_ESNI);

        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING) == TestResults.TRUE) {
            prettyAppendHeading(builder, "Tokenbinding Version");
            for (TokenBindingVersion version : report.getSupportedTokenbindingVersions()) {
                builder.append(version.toString()).append("\n");
            }

            prettyAppendHeading(builder, "Tokenbinding Key Parameters");
            for (TokenBindingKeyParameters keyParameter :
                    report.getSupportedTokenbindingKeyParameters()) {
                builder.append(keyParameter.toString()).append("\n");
            }
        }
        appendTls13Groups(builder);
        appendCurves(builder);
        appendSignatureAndHashAlgorithms(builder);
        return builder;
    }

    public StringBuilder appendAlpacaAttack(StringBuilder builder) {
        prettyAppendHeading(builder, "Alpaca Details");
        prettyAppend(builder, "Strict ALPN", TlsAnalyzedProperty.STRICT_ALPN);
        prettyAppend(builder, "Strict SNI", TlsAnalyzedProperty.STRICT_SNI);
        prettyAppend(builder, "ALPACA Mitigation", TlsAnalyzedProperty.ALPACA_MITIGATED);
        return builder;
    }

    public StringBuilder appendAlpn(StringBuilder builder) {
        @SuppressWarnings("unchecked")
        List<String> alpns = report.getSupportedAlpnConstans();
        if (alpns != null) {
            prettyAppendHeading(builder, "ALPN");
            for (AlpnProtocol alpnProtocol : AlpnProtocol.values()) {
                if (alpnProtocol.isGrease()) {
                    continue;
                }
                if (alpns.contains(alpnProtocol.getConstant())) {
                    prettyAppend(builder, alpnProtocol.getPrintableName(), true);
                } else {
                    if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                        prettyAppend(builder, alpnProtocol.getPrintableName(), false);
                    }
                }
            }
        }
        return builder;
    }

    public void appendRandomness(StringBuilder builder) {
        List<EntropyReport> entropyResults = report.getEntropyReports();
        if (entropyResults != null) {
            prettyAppendHeading(builder, "Entropy");
            prettyAppend(
                    builder, "Uses Unixtime", TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM);
            for (EntropyReport entropyReport : report.getEntropyReports()) {
                if (report.getProtocolType() == ProtocolType.TLS
                        && entropyReport.getType() == RandomType.COOKIE) {
                    continue;
                }
                prettyAppendSubheading(builder, entropyReport.getType().getHumanReadableName());
                prettyAppend(builder, "Datapoints", "" + entropyReport.getNumberOfValues());
                int bytesTotal = entropyReport.getNumberOfBytes();
                if (bytesTotal > 32000) {
                    prettyAppend(
                            builder, "Bytes total", "" + bytesTotal + " (good)", AnsiColor.GREEN);
                } else if (bytesTotal < 16000) {
                    prettyAppend(
                            builder,
                            "Bytes total",
                            "" + bytesTotal + " (not enough data collected)",
                            AnsiColor.RED);
                } else {
                    prettyAppend(
                            builder,
                            "Bytes total",
                            "" + bytesTotal + " (not siginificant)",
                            AnsiColor.YELLOW);
                }

                prettyAppend(builder, "Duplicates", entropyReport.isDuplicates());
                if (entropyReport.isDuplicates()) {
                    prettyAppend(
                            builder,
                            "Total duplicates",
                            "" + entropyReport.getNumberOfDuplicates());
                }
                prettyAppend(builder, "Failed Entropy Test", entropyReport.isFailedEntropyTest());
                prettyAppend(builder, "Failed Fourier Test", entropyReport.isFailedFourierTest());
                prettyAppend(
                        builder, "Failed Frequency Test", entropyReport.isFailedFrequencyTest());
                prettyAppend(builder, "Failed Runs Test", entropyReport.isFailedRunsTest());
                prettyAppend(
                        builder, "Failed Longest Run Test", entropyReport.isFailedLongestRunTest());
                prettyAppend(builder, "Failed Monobit Test", entropyReport.isFailedMonoBitTest());
                prettyAppend(
                        builder,
                        "Failed TemplateTests",
                        ""
                                + (Math.round(
                                                entropyReport.getFailedTemplateTestPercentage()
                                                        * 100.0)
                                        / 100.0)
                                + " %");
            }
        }
    }

    public void appendPublicKeyIssues(StringBuilder builder) {
        prettyAppendHeading(builder, "PublicKey Parameter");
        prettyAppend(builder, "EC PublicKey reuse", TlsAnalyzedProperty.REUSES_EC_PUBLICKEY);
        prettyAppend(builder, "DH PublicKey reuse", TlsAnalyzedProperty.REUSES_DH_PUBLICKEY);
        prettyAppend(
                builder, "Uses Common DH Primes", TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES);
        if (report.getCommonDhValues() != null && report.getCommonDhValues().size() != 0) {
            for (CommonDhValues value : report.getCommonDhValues()) {
                prettyAppend(builder, "\t" + value.getName(), AnsiColor.YELLOW);
            }
        }
        prettyAppend(
                builder, "Uses only prime moduli", TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI);
        prettyAppend(
                builder,
                "Uses only safe-prime moduli",
                TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI);
        if (report.getWeakestDhStrength() != null) {
            if (report.getWeakestDhStrength() < 1000) {
                prettyAppend(
                        builder, "DH Strength", "" + report.getWeakestDhStrength(), AnsiColor.RED);
            } else if (report.getWeakestDhStrength() < 2000) {
                prettyAppend(
                        builder,
                        "DH Strength",
                        "" + report.getWeakestDhStrength(),
                        AnsiColor.YELLOW);
            } else if (report.getWeakestDhStrength() < 4100) {
                prettyAppend(
                        builder,
                        "DH Strength",
                        "" + report.getWeakestDhStrength(),
                        AnsiColor.GREEN);
            } else {
                prettyAppend(
                        builder,
                        "DH Strength",
                        "" + report.getWeakestDhStrength(),
                        AnsiColor.YELLOW);
            }
        }
    }

    public void appendScoringResults(StringBuilder builder) {
        if (report.getScoreReport() == null) {
            return;
        }
        SiteReportRater rater;
        prettyAppendHeading(builder, "Scoring results");
        try {
            rater = DefaultRatingLoader.getServerReportRater("en");
            prettyAppend(builder, "Score: " + report.getScoreReport().getScore());
            if (!detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                return;
            }
            prettyAppend(builder, "");
            Recommendations recommendations = rater.getRecommendations();
            report.getScoreReport()
                    .getInfluencers()
                    .entrySet()
                    .forEach(
                            (entry) -> {
                                PropertyResultRatingInfluencer influencer = entry.getValue();
                                Recommendation recommendation =
                                        recommendations.getRecommendation(entry.getKey());
                                int scoreInfluence = 0;
                                StringBuilder additionalInfo = new StringBuilder();
                                if (influencer.getReferencedProperty() != null) {
                                    additionalInfo
                                            .append(" (Score: 0). -> See ")
                                            .append(influencer.getReferencedProperty())
                                            .append(" for more information");
                                } else {
                                    scoreInfluence = influencer.getInfluence();
                                    additionalInfo
                                            .append(" (Score: ")
                                            .append((scoreInfluence > 0 ? "+" : ""))
                                            .append(scoreInfluence);
                                    if (influencer.hasScoreCap()) {
                                        additionalInfo
                                                .append(", Score cap: ")
                                                .append(influencer.getScoreCap());
                                    }
                                    additionalInfo.append(")");
                                }
                                String result =
                                        recommendation.getShortName()
                                                + ": "
                                                + influencer.getResult()
                                                + additionalInfo;
                                if (scoreInfluence > 0) {
                                    prettyAppend(builder, result, AnsiColor.GREEN);
                                } else if (scoreInfluence < -50) {
                                    prettyAppend(builder, result, AnsiColor.RED);
                                } else if (scoreInfluence < 0) {
                                    prettyAppend(builder, result, AnsiColor.YELLOW);
                                }
                            });
        } catch (Exception ex) {
            LOGGER.error(ex);
            prettyAppend(builder, "Could not append scoring results", AnsiColor.RED);
        }
    }

    public void appendGuidelines(StringBuilder builder) {
        List<GuidelineReport> guidelineReports = report.getGuidelineReports();
        if (this.report.getGuidelineReports() != null
                && this.report.getGuidelineReports().size() > 0) {
            prettyAppendHeading(builder, "Guidelines");
            for (GuidelineReport report : guidelineReports) {
                appendGuideline(builder, report);
            }
        }
    }

    private void appendGuideline(StringBuilder builder, GuidelineReport guidelineReport) {
        prettyAppendSubheading(builder, "Guideline " + StringUtils.trim(guidelineReport.getName()));
        prettyAppend(builder, "Passed: " + guidelineReport.getPassed().size(), AnsiColor.GREEN);
        prettyAppend(builder, "Skipped: " + guidelineReport.getSkipped().size());
        prettyAppend(builder, "Failed: " + guidelineReport.getFailed().size(), AnsiColor.RED);
        prettyAppend(
                builder, "Uncertain: " + guidelineReport.getUncertain().size(), AnsiColor.YELLOW);
        if (this.detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            prettyAppend(builder, StringUtils.trim(guidelineReport.getLink()), AnsiColor.BLUE);

            if (this.detail.isGreaterEqualTo(ScannerDetail.ALL)) {
                prettyAppendSubSubheading(builder, "Passed Checks:");
                for (GuidelineCheckResult result : guidelineReport.getPassed()) {
                    prettyAppend(builder, StringUtils.trim(result.getName()), AnsiColor.GREEN);
                    prettyAppend(
                            builder,
                            "\t" + StringUtils.trim(result.display()).replace("\n", "\n\t"));
                }
            }
            prettyAppendSubSubheading(builder, "Failed Checks:");
            for (GuidelineCheckResult result : guidelineReport.getFailed()) {
                prettyAppend(builder, StringUtils.trim(result.getName()), AnsiColor.RED);
                prettyAppend(
                        builder, "\t" + StringUtils.trim(result.display()).replace("\n", "\n\t"));
            }
            prettyAppendSubSubheading(builder, "Uncertain Checks:");
            for (GuidelineCheckResult result : guidelineReport.getUncertain()) {
                prettyAppend(builder, StringUtils.trim(result.getName()), AnsiColor.YELLOW);
                prettyAppend(
                        builder, "\t" + StringUtils.trim(result.display()).replace("\n", "\n\t"));
            }

            if (this.detail.isGreaterEqualTo(ScannerDetail.ALL)) {
                prettyAppendSubSubheading(builder, "Skipped Checks:");
                for (GuidelineCheckResult result : guidelineReport.getSkipped()) {
                    prettyAppend(builder, StringUtils.trim(result.getName()));
                    prettyAppend(
                            builder,
                            "\t" + StringUtils.trim(result.display()).replace("\n", "\n\t"));
                }
            }
        }
    }

    public void appendRecommendations(StringBuilder builder) {
        if (report.getScoreReport() == null) {
            return;
        }
        prettyAppendHeading(builder, "Recommendations");
        SiteReportRater rater;
        try {
            rater = DefaultRatingLoader.getServerReportRater("en");

            ScoreReport scoreReport = report.getScoreReport();
            Recommendations recommendations = rater.getRecommendations();
            LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> influencers =
                    scoreReport.getInfluencers();
            influencers.entrySet().stream()
                    .sorted(Map.Entry.comparingByValue())
                    .forEach(
                            (entry) -> {
                                PropertyResultRatingInfluencer influencer = entry.getValue();
                                if (influencer.isBadInfluence()
                                        || influencer.getReferencedProperty() != null) {
                                    Recommendation recommendation =
                                            recommendations.getRecommendation(entry.getKey());
                                    PropertyResultRecommendation resultRecommendation =
                                            recommendation.getPropertyResultRecommendation(
                                                    influencer.getResult());
                                    if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
                                        printFullRecommendation(
                                                builder,
                                                recommendation,
                                                influencer,
                                                resultRecommendation);
                                    } else {
                                        printShortRecommendation(
                                                builder, influencer, resultRecommendation);
                                    }
                                }
                            });
        } catch (Exception ex) {
            prettyAppend(
                    builder, "Could not append recommendations - unrelated error", AnsiColor.RED);
            LOGGER.error("Could not append recommendations", ex);
        }
    }

    private void printFullRecommendation(
            StringBuilder builder,
            Recommendation recommendation,
            PropertyResultRatingInfluencer influencer,
            PropertyResultRecommendation resultRecommendation) {
        if (report.getScoreReport() == null) {
            return;
        }
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(builder, "", color);
        prettyAppend(builder, recommendation.getShortName() + ": " + influencer.getResult(), color);
        int scoreInfluence = 0;
        String additionalInfo = "";
        SiteReportRater rater;

        try {
            rater = DefaultRatingLoader.getServerReportRater("en");

            if (influencer.getReferencedProperty() != null) {
                scoreInfluence =
                        rater.getRatingInfluencers()
                                .getPropertyRatingInfluencer(
                                        influencer.getReferencedProperty(),
                                        influencer.getReferencedPropertyResult())
                                .getInfluence();
                Recommendation r =
                        rater.getRecommendations()
                                .getRecommendation(influencer.getReferencedProperty());
                additionalInfo = " -> This score comes from \"" + r.getShortName() + "\"";
            } else {
                scoreInfluence = influencer.getInfluence();
            }
            prettyAppend(builder, "  Score: " + scoreInfluence + additionalInfo, color);
            if (influencer.hasScoreCap()) {
                prettyAppend(builder, "  Score cap: " + influencer.getScoreCap(), color);
            }
            prettyAppend(
                    builder, "  Information: " + resultRecommendation.getShortDescription(), color);
            prettyAppend(
                    builder,
                    "  Recommendation: " + resultRecommendation.getHandlingRecommendation(),
                    color);
        } catch (Exception ex) {
            prettyAppend(
                    builder,
                    "Could not append recommendations - recommendations or ratingInfluencers not found: "
                            + recommendation.getShortName(),
                    AnsiColor.RED);
            LOGGER.error(
                    "Could not append recommendations for: " + recommendation.getShortName(), ex);
        }
    }

    private void printShortRecommendation(
            StringBuilder builder,
            PropertyResultRatingInfluencer influencer,
            PropertyResultRecommendation resultRecommendation) {
        AnsiColor color = getRecommendationColor(influencer);
        prettyAppend(
                builder,
                resultRecommendation.getShortDescription()
                        + ". "
                        + resultRecommendation.getHandlingRecommendation(),
                color);
    }

    private AnsiColor getRecommendationColor(PropertyResultRatingInfluencer influencer) {
        if (influencer.getInfluence() <= -200) {
            return AnsiColor.RED;
        } else if (influencer.getInfluence() < -50) {
            return AnsiColor.YELLOW;
        } else if (influencer.getInfluence() > 0) {
            return AnsiColor.GREEN;
        }
        return AnsiColor.DEFAULT_COLOR;
    }

    private void prettyPrintCipherSuite(StringBuilder builder, CipherSuite suite) {
        CipherSuiteGrade grade = CipherSuiteRater.getGrade(suite);
        switch (grade) {
            case GOOD:
                prettyAppend(builder, suite.name(), AnsiColor.GREEN);
                break;
            case LOW:
                prettyAppend(builder, suite.name(), AnsiColor.RED);
                break;
            case MEDIUM:
                prettyAppend(builder, suite.name(), AnsiColor.YELLOW);
                break;
            case NONE:
                prettyAppend(builder, suite.name());
                break;
            default:
                prettyAppend(builder, suite.name());
        }
    }

    public StringBuilder appendCurves(StringBuilder builder) {
        List<NamedGroup> namedGroups = report.getSupportedNamedGroups();
        if (namedGroups != null) {
            prettyAppendHeading(builder, "Supported Named Groups");
            if (namedGroups.size() > 0) {
                for (NamedGroup group : namedGroups) {
                    builder.append(group.name());
                    if (detail == ScannerDetail.ALL) {
                        builder.append("\n  Found using:");
                        NamedGroupWitness witness =
                                report.getSupportedNamedGroupsWitnesses().get(group);
                        for (CipherSuite cipher : witness.getCipherSuites()) {
                            builder.append("\n    ").append(cipher.toString());
                        }
                        builder.append("\n  ECDSA Required Groups:");
                        if (witness.getEcdsaPkGroupEphemeral() != null
                                && witness.getEcdsaPkGroupEphemeral() != group) {
                            builder.append("\n    ")
                                    .append(witness.getEcdsaPkGroupEphemeral())
                                    .append(" (Certificate Public Key - Ephemeral Cipher Suite)");
                        }
                        if (witness.getEcdsaSigGroupEphemeral() != null
                                && witness.getEcdsaSigGroupEphemeral() != group) {
                            builder.append("\n    ")
                                    .append(witness.getEcdsaSigGroupEphemeral())
                                    .append(" (Certificate Signature  - Ephemeral Cipher Suite)");
                        }
                        if (witness.getEcdsaSigGroupStatic() != null
                                && witness.getEcdsaSigGroupStatic() != group) {
                            builder.append("\n    ")
                                    .append(witness.getEcdsaSigGroupStatic())
                                    .append(" (Certificate Signature  - Static Cipher Suite)");
                        }
                    }
                    builder.append("\n");
                }
                if (report.getResult(TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER)
                        == TestResults.TRUE) {
                    prettyAppend(builder, "Not all Groups are supported for all Cipher Suites");
                }
                if (report.getResult(TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY)
                        == TestResults.TRUE) {
                    prettyAppend(
                            builder,
                            "Groups required for ECDSA validation are not enforced",
                            AnsiColor.YELLOW);
                }
                prettyAppendHeading(builder, "NamedGroups General");
                prettyAppend(
                        builder,
                        "Enforces client's named group ordering",
                        TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING);
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public StringBuilder appendSignatureAndHashAlgorithms(StringBuilder builder) {
        List<SignatureAndHashAlgorithm> algorithms =
                report.getSupportedSignatureAndHashAlgorithms();
        if (algorithms != null) {
            prettyAppendHeading(builder, "Supported Signature and Hash Algorithms");
            if (report.getSupportedSignatureAndHashAlgorithms().size() > 0) {
                for (SignatureAndHashAlgorithm algorithm :
                        report.getSupportedSignatureAndHashAlgorithms()) {
                    prettyAppend(builder, algorithm.toString());
                }
                prettyAppendHeading(builder, "Signature and Hash Algorithms General");
                prettyAppend(
                        builder,
                        "Enforces client's signature has algorithm ordering",
                        TlsAnalyzedProperty.ENFORCES_SIGNATURE_HASH_ALGORITHM_ORDERING);
            } else {
                builder.append("none\n");
            }
        }
        List<SignatureAndHashAlgorithm> algorithmsTls13 =
                report.getSupportedSignatureAndHashAlgorithmsTls13();
        if (algorithmsTls13 != null) {
            prettyAppendHeading(builder, "Supported Signature and Hash Algorithms TLS 1.3");
            if (report.getSupportedSignatureAndHashAlgorithmsTls13().size() > 0) {
                for (SignatureAndHashAlgorithm algorithm :
                        report.getSupportedSignatureAndHashAlgorithmsTls13()) {
                    prettyAppend(builder, algorithm.toString());
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public StringBuilder appendCompressions(StringBuilder builder) {
        prettyAppendHeading(builder, "Supported Compressions");
        List<CompressionMethod> compressions = report.getSupportedCompressionMethods();
        if (compressions != null) {

            for (CompressionMethod compression : compressions) {
                prettyAppend(builder, compression.name());
            }
        }
        return builder;
    }

    public StringBuilder appendTls13Groups(StringBuilder builder) {
        List<NamedGroup> tls13Groups = report.getSupportedTls13Groups();
        if (tls13Groups != null) {
            prettyAppendHeading(builder, "TLS 1.3 Named Groups");
            if (tls13Groups.size() > 0) {
                for (NamedGroup group : tls13Groups) {
                    builder.append(group.name()).append("\n");
                }
            } else {
                builder.append("none\n");
            }
        }
        return builder;
    }

    public void appendPerformanceData(StringBuilder builder) {
        if (detail.isGreaterEqualTo(ScannerDetail.ALL)) {
            prettyAppendHeading(builder, "Scanner Performance");
            try {
                if (report.getProtocolType() == ProtocolType.TLS) {
                    prettyAppend(
                            builder, "TCP connections", "" + report.getPerformedTcpConnections());
                }
                prettyAppendSubheading(builder, "Probe execution performance");
                for (PerformanceData data : report.getPerformanceList()) {
                    Period period = new Period(data.getStopTime() - data.getStartTime());
                    prettyAppend(
                            builder,
                            padToLength(data.getType().getName(), 25)
                                    + " "
                                    + PeriodFormat.getDefault().print(period));
                }
            } catch (Exception e) {
                prettyAppend(builder, "Error: " + e.getMessage());
            }
        } else {
            LOGGER.debug("Not printing performance data.");
        }
    }

    private void appendClientAuthentication(StringBuilder builder) {
        prettyAppendHeading(builder, "Client authentication");
        prettyAppend(builder, "Supported", report.getCcaSupported());
        prettyAppend(builder, "Required", report.getCcaRequired());

        if (report.getCcaTestResultList() != null) {
            List<CcaTestResult> ccaTestResults = report.getCcaTestResultList();
            ccaTestResults.sort(
                    new Comparator<CcaTestResult>() {
                        @Override
                        public int compare(CcaTestResult ccaTestResult, CcaTestResult t1) {
                            int c;
                            c = ccaTestResult.getWorkflowType().compareTo(t1.getWorkflowType());
                            if (c != 0) {
                                return c;
                            }

                            c =
                                    ccaTestResult
                                            .getCertificateType()
                                            .compareTo(t1.getCertificateType());
                            if (c != 0) {
                                return c;
                            }

                            c =
                                    ccaTestResult
                                            .getProtocolVersion()
                                            .compareTo(t1.getProtocolVersion());
                            if (c != 0) {
                                return c;
                            }

                            c = ccaTestResult.getCipherSuite().compareTo(t1.getCipherSuite());
                            return c;
                        }
                    });
            CcaWorkflowType lastCcaWorkflowType = null;
            CcaCertificateType lastCcaCertificateType = null;
            ProtocolVersion lastProtocolVersion = null;
            for (CcaTestResult ccaTestResult : ccaTestResults) {
                if (ccaTestResult.getWorkflowType() != lastCcaWorkflowType) {
                    lastCcaWorkflowType = ccaTestResult.getWorkflowType();
                    prettyAppendSubheading(builder, lastCcaWorkflowType.name());
                }
                if (ccaTestResult.getCertificateType() != lastCcaCertificateType) {
                    lastCcaCertificateType = ccaTestResult.getCertificateType();
                    prettyAppendSubSubheading(builder, lastCcaCertificateType.name());
                }
                if (ccaTestResult.getProtocolVersion() != lastProtocolVersion) {
                    lastProtocolVersion = ccaTestResult.getProtocolVersion();
                    prettyAppendSubSubSubheading(builder, lastProtocolVersion.name());
                }
                prettyAppend(
                        builder,
                        ccaTestResult
                                .getWorkflowType()
                                .name()
                                .concat("--")
                                .concat(ccaTestResult.getCertificateType().name())
                                .concat("--")
                                .concat(ccaTestResult.getProtocolVersion().name())
                                .concat("--")
                                .concat(ccaTestResult.getCipherSuite().name()),
                        ccaTestResult.getSucceeded(),
                        ccaTestResult.getSucceeded() ? AnsiColor.RED : AnsiColor.GREEN);
            }
        }
    }

    private StringBuilder appendSessionTicketZeroKeyDetails(StringBuilder builder) {
        if (report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY)
                == TestResults.TRUE) {
            prettyAppendHeading(builder, "Session Ticket Zero Key Attack Details");
            prettyAppend(
                    builder,
                    "Has GnuTls magic bytes:",
                    TlsAnalyzedProperty.HAS_GNU_TLS_MAGIC_BYTES);
        }
        return builder;
    }
}
