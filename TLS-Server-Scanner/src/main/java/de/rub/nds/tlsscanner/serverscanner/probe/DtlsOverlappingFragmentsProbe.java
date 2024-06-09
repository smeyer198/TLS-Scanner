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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.overlappingfragments.CipherSuiteTestVectors;
import de.rub.nds.tlsscanner.serverscanner.probe.overlappingfragments.ClientKeyExchangeTestVectors;
import de.rub.nds.tlsscanner.serverscanner.probe.overlappingfragments.OverlappingFragmentSupport;
import de.rub.nds.tlsscanner.serverscanner.probe.overlappingfragments.SignatureAndHashAlgorithmTestVectors;
import de.rub.nds.tlsscanner.serverscanner.probe.overlappingfragments.VersionTestVectors;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import de.upb.cs.OverlappingFragmentAnalysis;
import de.upb.cs.analysis.AbstractAnalysis;
import de.upb.cs.analysis.AnalysisResults;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.MessageType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class DtlsOverlappingFragmentsProbe extends TlsServerProbe {

    private List<ProtocolVersion> supportedProtocolVersions;
    private List<CipherSuite> supportedCipherSuites;
    private SignatureAndHashAlgorithm certificateAlgorithm;
    private boolean supportsCookieExchange = true;
    private boolean requiresClientAuthentication = false;
    private static final boolean individualFragments = true;

    // Accepts overlapping fragments
    private TestResult acceptsClientHelloConsecutiveFragments = TestResults.NOT_TESTED_YET;
    private TestResult acceptsClientHelloSubsequentFragments = TestResults.NOT_TESTED_YET;
    private TestResult acceptsClientHelloExtendedSubsequentFragments = TestResults.NOT_TESTED_YET;

    private TestResult acceptsClientKeyExchangeConsecutiveFragments = TestResults.NOT_TESTED_YET;
    private TestResult acceptsClientKeyExchangeSubsequentFragments = TestResults.NOT_TESTED_YET;
    private TestResult acceptsClientKeyExchangeExtendedSubsequentFragments =
            TestResults.NOT_TESTED_YET;

    // Version test results
    private TestResult consecutiveVersionTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult consecutiveVersionTypeBOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentVersionTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentVersionTypeBOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentVersionTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentVersionTypeBOriginalOrder = TestResults.NOT_TESTED_YET;

    private TestResult consecutiveVersionTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult consecutiveVersionTypeBReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentVersionTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentVersionTypeBReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentVersionTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentVersionTypeBReversedOrder = TestResults.NOT_TESTED_YET;

    // CipherSuites test result
    private TestResult consecutiveCipherSuitesTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult consecutiveCipherSuitesTypeBOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentCipherSuitesTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentCipherSuitesTypeBOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentCipherSuitesTypeAOriginalOrder =
            TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentCipherSuitesTypeBOriginalOrder =
            TestResults.NOT_TESTED_YET;

    private TestResult consecutiveCipherSuitesTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult consecutiveCipherSuitesTypeBReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentCipherSuitesTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentCipherSuitesTypeBReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentCipherSuitesTypeAReversedOrder =
            TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentCipherSuitesTypeBReversedOrder =
            TestResults.NOT_TESTED_YET;

    // SignatureAndHashAlgorithms
    private TestResult consecutiveSigAndHashTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult consecutiveSigAndHashTypeBOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentSigAndHashTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentSigAndHashTypeBOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentSigAndHashTypeAOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentSigAndHashTypeBOriginalOrder = TestResults.NOT_TESTED_YET;

    private TestResult consecutiveSigAndHashTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult consecutiveSigAndHashTypeBReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentSigAndHashTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult subsequentSigAndHashTypeBReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentSigAndHashTypeAReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult extendedSubsequentSigAndHashTypeBReversedOrder = TestResults.NOT_TESTED_YET;

    // ClientKeyExchange test results
    private TestResult rsaClientKeyExchangeOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult dhClientKeyExchangeOriginalOrder = TestResults.NOT_TESTED_YET;
    private TestResult ecdhClientKeyExchangeOriginalOrder = TestResults.NOT_TESTED_YET;

    private TestResult rsaClientKeyExchangeReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult dhClientKeyExchangeReversedOrder = TestResults.NOT_TESTED_YET;
    private TestResult ecdhClientKeyExchangeReversedOrder = TestResults.NOT_TESTED_YET;

    public DtlsOverlappingFragmentsProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_OVERLAPPING_FRAGMENTS, configSelector);

        // Assume false
        register(TlsAnalyzedProperty.HAS_MULTIPLE_CERTIFICATES);
        put(TlsAnalyzedProperty.HAS_MULTIPLE_CERTIFICATES, TestResults.FALSE);

        register(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_CONSECUTIVE_FRAGMENTS,
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_SUBSEQUENT_FRAGMENTS,
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_EXTENDED_SUBSEQUENT_FRAGMENTS);

        register(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_CONSECUTIVE_FRAGMENTS,
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_SUBSEQUENT_FRAGMENTS,
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_EXTENDED_SUBSEQUENT_FRAGMENTS);

        register(
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_B_ORIGINAL_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_B_ORIGINAL_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_B_ORIGINAL_ORDER);

        register(
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_B_REVERSED_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_B_REVERSED_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_B_REVERSED_ORDER);

        register(
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER);

        register(
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_B_REVERSED_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_B_REVERSED_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_B_REVERSED_ORDER);

        register(
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER);

        register(
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_B_REVERSED_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_B_REVERSED_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_A_REVERSED_ORDER,
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_B_REVERSED_ORDER);

        register(
                TlsAnalyzedProperty.RSA_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER,
                TlsAnalyzedProperty.DH_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER,
                TlsAnalyzedProperty.ECDH_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER);

        register(
                TlsAnalyzedProperty.RSA_CLIENT_KEY_EXCHANGE_REVERSED_ORDER,
                TlsAnalyzedProperty.DH_CLIENT_KEY_EXCHANGE_REVERSED_ORDER,
                TlsAnalyzedProperty.ECDH_CLIENT_KEY_EXCHANGE_REVERSED_ORDER);
    }

    @Override
    public void executeTest() {
        if (requiresClientAuthentication) {
            cannotTestOverlappingFragmentSupport();
            cannotTestVersionOriginalOrder();
            cannotTestVersionReversedOrder();
            cannotTestCipherSuitesOriginalOrder();
            cannotTestCipherSuitesReversedOrder();
            cannotTestSignatureAndHashAlgorithmsOriginalOrder();
            cannotTestSignatureAndHashAlgorithmsReversedOrder();
            cannotTestClientKeyExchange();
            return;
        }

        testOverlappingFragmentSupport();

        // Original order
        executeVersionTestVectorsOriginalOrder();
        executeCipherSuiteTestVectorsOriginalOrder();
        if (supportedProtocolVersions.contains(ProtocolVersion.DTLS12)) {
            executeSignatureAndHashAlgorithmsTestVectorsOriginalOrder();
        } else {
            cannotTestSignatureAndHashAlgorithmsOriginalOrder();
        }
        executeClientKeyExchangeTestVectorsOriginalOrder();

        // Reversed Order
        executeVersionTestVectorsReversedOrder();
        executeCipherSuiteTestVectorsReversedOrder();
        if (supportedProtocolVersions.contains(ProtocolVersion.DTLS12)) {
            executeSignatureAndHashAlgorithmsTestVectorsReversedOrder();
        } else {
            cannotTestSignatureAndHashAlgorithmsReversedOrder();
        }
        executeClientKeyExchangeTestVectorsReversedOrder();
    }

    public AnalysisConfig initializeAnalysisConfig() {
        Config baseConfig = configSelector.getBaseConfig();
        AnalysisConfig analysisConfig = new AnalysisConfig();

        analysisConfig.setTlsAttackerConfig(baseConfig);
        analysisConfig.setMessageType(MessageType.CLIENT_HELLO);

        analysisConfig.setCookieExchange(supportsCookieExchange);
        analysisConfig.setClientHelloCipherSuites(new ArrayList<>(supportedCipherSuites));
        analysisConfig.setUseIndividualDatagrams(individualFragments);

        return analysisConfig;
    }

    public void testOverlappingFragmentSupport() {
        OverlappingFragmentSupport support = new OverlappingFragmentSupport(this);

        acceptsClientHelloConsecutiveFragments = support.acceptsClientHelloConsecutiveFragments();
        acceptsClientHelloSubsequentFragments = support.acceptsClientHelloSubsequentFragments();
        acceptsClientHelloExtendedSubsequentFragments =
                support.acceptsClientHelloExtendedSubsequentFragments();

        acceptsClientKeyExchangeConsecutiveFragments =
                support.acceptsClientKeyExchangeConsecutiveFragments(supportedCipherSuites);
        acceptsClientKeyExchangeSubsequentFragments =
                support.acceptsClientKeyExchangeSubsequentFragments(supportedCipherSuites);
        acceptsClientKeyExchangeExtendedSubsequentFragments =
                support.acceptsClientKeyExchangeExtendedSubsequentFragments(supportedCipherSuites);
    }

    private void cannotTestOverlappingFragmentSupport() {
        acceptsClientHelloConsecutiveFragments = TestResults.CANNOT_BE_TESTED;
        acceptsClientHelloSubsequentFragments = TestResults.CANNOT_BE_TESTED;
        acceptsClientHelloExtendedSubsequentFragments = TestResults.CANNOT_BE_TESTED;
    }

    public void executeVersionTestVectorsOriginalOrder() {
        VersionTestVectors versionTestVectors = new VersionTestVectors(this);

        Optional<ProtocolVersion> highestProtocolVersion =
                versionTestVectors.getHighestProtocolVersion(supportedProtocolVersions);
        if (highestProtocolVersion.isEmpty()) {
            cannotTestVersionOriginalOrder();
            return;
        }

        if (supportsConsecutiveOverlappingFragments()) {
            consecutiveVersionTypeAOriginalOrder =
                    versionTestVectors.consecutiveTypeAOriginalOrder(highestProtocolVersion.get());
            consecutiveVersionTypeBOriginalOrder =
                    versionTestVectors.consecutiveTypeBOriginalOrder(highestProtocolVersion.get());
        } else {
            consecutiveVersionTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            consecutiveVersionTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsSubsequentOverlappingFragments()) {
            subsequentVersionTypeAOriginalOrder =
                    versionTestVectors.subsequentTypeAOriginalOrder(highestProtocolVersion.get());
            subsequentVersionTypeBOriginalOrder =
                    versionTestVectors.subsequentTypeBOriginalOrder(highestProtocolVersion.get());
        } else {
            subsequentVersionTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            subsequentVersionTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsExtendedSubsequentOverlappingFragments()) {
            extendedSubsequentVersionTypeAOriginalOrder =
                    versionTestVectors.extendedSubsequentTypeAOriginalOrder(
                            highestProtocolVersion.get());
            extendedSubsequentVersionTypeBOriginalOrder =
                    versionTestVectors.extendedSubsequentTypeBOriginalOrder(
                            highestProtocolVersion.get());
        } else {
            extendedSubsequentVersionTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            extendedSubsequentVersionTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }
    }

    private void cannotTestVersionOriginalOrder() {
        consecutiveVersionTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        consecutiveVersionTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
        subsequentVersionTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        subsequentVersionTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentVersionTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentVersionTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
    }

    public void executeVersionTestVectorsReversedOrder() {
        VersionTestVectors versionTestVectors = new VersionTestVectors(this);

        Optional<ProtocolVersion> highestProtocolVersion =
                versionTestVectors.getHighestProtocolVersion(supportedProtocolVersions);
        if (highestProtocolVersion.isEmpty()) {
            cannotTestVersionReversedOrder();
            return;
        }

        if (supportsConsecutiveOverlappingFragments()) {
            consecutiveVersionTypeAReversedOrder =
                    versionTestVectors.consecutiveTypeAReversedOrder(highestProtocolVersion.get());
            consecutiveVersionTypeBReversedOrder =
                    versionTestVectors.consecutiveTypeBReversedOrder(highestProtocolVersion.get());
        } else {
            consecutiveVersionTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            consecutiveVersionTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsSubsequentOverlappingFragments()) {
            subsequentVersionTypeAReversedOrder =
                    versionTestVectors.subsequentTypeAReversedOrder(highestProtocolVersion.get());
            subsequentVersionTypeBReversedOrder =
                    versionTestVectors.subsequentTypeBReversedOrder(highestProtocolVersion.get());
        } else {
            subsequentVersionTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            subsequentVersionTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsExtendedSubsequentOverlappingFragments()) {
            extendedSubsequentVersionTypeAReversedOrder =
                    versionTestVectors.extendedSubsequentTypeAReversedOrder(
                            highestProtocolVersion.get());
            extendedSubsequentVersionTypeBReversedOrder =
                    versionTestVectors.extendedSubsequentTypeBReversedOrder(
                            highestProtocolVersion.get());
        } else {
            extendedSubsequentVersionTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            extendedSubsequentVersionTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }
    }

    private void cannotTestVersionReversedOrder() {
        consecutiveVersionTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        consecutiveVersionTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
        subsequentVersionTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        subsequentVersionTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentVersionTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentVersionTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
    }

    public void executeCipherSuiteTestVectorsOriginalOrder() {
        CipherSuiteTestVectors cipherSuiteTestVectors = new CipherSuiteTestVectors(this);
        List<CipherSuite> similarCipherSuites =
                cipherSuiteTestVectors.getSimilarCipherSuites(supportedCipherSuites);

        if (similarCipherSuites.isEmpty()) {
            cannotTestCipherSuitesOriginalOrder();
            return;
        }

        Optional<CipherSuite> preferredCipherSuite =
                cipherSuiteTestVectors.getPreferredCipherSuite(similarCipherSuites);
        if (preferredCipherSuite.isEmpty()) {
            cannotTestCipherSuitesOriginalOrder();
            return;
        }

        List<CipherSuite> orderedCipherSuites;
        if (preferredCipherSuite.get().equals(similarCipherSuites.get(0))) {
            orderedCipherSuites =
                    Arrays.asList(similarCipherSuites.get(0), similarCipherSuites.get(1));
        } else if (preferredCipherSuite.get().equals(similarCipherSuites.get(1))) {
            orderedCipherSuites =
                    Arrays.asList(similarCipherSuites.get(1), similarCipherSuites.get(0));
        } else {
            cannotTestCipherSuitesOriginalOrder();
            return;
        }

        if (supportsConsecutiveOverlappingFragments()) {
            consecutiveCipherSuitesTypeAOriginalOrder =
                    cipherSuiteTestVectors.consecutiveTypeAOriginalOrder(orderedCipherSuites);
            consecutiveCipherSuitesTypeBOriginalOrder =
                    cipherSuiteTestVectors.consecutiveTypeBOriginalOrder(orderedCipherSuites);
        } else {
            consecutiveCipherSuitesTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            consecutiveCipherSuitesTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsSubsequentOverlappingFragments()) {
            subsequentCipherSuitesTypeAOriginalOrder =
                    cipherSuiteTestVectors.subsequentTypeAOriginalOrder(orderedCipherSuites);
            subsequentCipherSuitesTypeBOriginalOrder =
                    cipherSuiteTestVectors.subsequentTypeBOriginalOrder(orderedCipherSuites);
        } else {
            subsequentCipherSuitesTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            subsequentCipherSuitesTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsExtendedSubsequentOverlappingFragments()) {
            extendedSubsequentCipherSuitesTypeAOriginalOrder =
                    cipherSuiteTestVectors.extendedSubsequentTypeAOriginalOrder(
                            orderedCipherSuites);
            extendedSubsequentCipherSuitesTypeBOriginalOrder =
                    cipherSuiteTestVectors.extendedSubsequentTypeBOriginalOrder(
                            orderedCipherSuites);
        } else {
            extendedSubsequentCipherSuitesTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            extendedSubsequentCipherSuitesTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }
    }

    private void cannotTestCipherSuitesOriginalOrder() {
        consecutiveCipherSuitesTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        consecutiveCipherSuitesTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
        subsequentCipherSuitesTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        subsequentCipherSuitesTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentCipherSuitesTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentCipherSuitesTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
    }

    public void executeCipherSuiteTestVectorsReversedOrder() {
        CipherSuiteTestVectors cipherSuiteTestVectors = new CipherSuiteTestVectors(this);
        List<CipherSuite> similarCipherSuites =
                cipherSuiteTestVectors.getSimilarCipherSuites(supportedCipherSuites);

        if (similarCipherSuites.isEmpty()) {
            cannotTestCipherSuitesReversedOrder();
            return;
        }

        Optional<CipherSuite> preferredCipherSuite =
                cipherSuiteTestVectors.getPreferredCipherSuite(similarCipherSuites);
        if (preferredCipherSuite.isEmpty()) {
            cannotTestCipherSuitesReversedOrder();
            return;
        }

        List<CipherSuite> orderedCipherSuites;
        if (preferredCipherSuite.get().equals(similarCipherSuites.get(0))) {
            orderedCipherSuites =
                    Arrays.asList(similarCipherSuites.get(0), similarCipherSuites.get(1));
        } else if (preferredCipherSuite.get().equals(similarCipherSuites.get(1))) {
            orderedCipherSuites =
                    Arrays.asList(similarCipherSuites.get(1), similarCipherSuites.get(0));
        } else {
            cannotTestCipherSuitesReversedOrder();
            return;
        }

        if (supportsConsecutiveOverlappingFragments()) {
            consecutiveCipherSuitesTypeAReversedOrder =
                    cipherSuiteTestVectors.consecutiveTypeAReversedOrder(orderedCipherSuites);
            consecutiveCipherSuitesTypeBReversedOrder =
                    cipherSuiteTestVectors.consecutiveTypeBReversedOrder(orderedCipherSuites);
        } else {
            consecutiveCipherSuitesTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            consecutiveCipherSuitesTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsSubsequentOverlappingFragments()) {
            subsequentCipherSuitesTypeAReversedOrder =
                    cipherSuiteTestVectors.subsequentTypeAReversedOrder(orderedCipherSuites);
            subsequentCipherSuitesTypeBReversedOrder =
                    cipherSuiteTestVectors.subsequentTypeBReversedOrder(orderedCipherSuites);
        } else {
            subsequentCipherSuitesTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            subsequentCipherSuitesTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsExtendedSubsequentOverlappingFragments()) {
            extendedSubsequentCipherSuitesTypeAReversedOrder =
                    cipherSuiteTestVectors.extendedSubsequentTypeAReversedOrder(
                            orderedCipherSuites);
            extendedSubsequentCipherSuitesTypeBReversedOrder =
                    cipherSuiteTestVectors.extendedSubsequentTypeBReversedOrder(
                            orderedCipherSuites);
        } else {
            extendedSubsequentCipherSuitesTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            extendedSubsequentCipherSuitesTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }
    }

    private void cannotTestCipherSuitesReversedOrder() {
        consecutiveCipherSuitesTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        consecutiveCipherSuitesTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
        subsequentCipherSuitesTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        subsequentCipherSuitesTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentCipherSuitesTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentCipherSuitesTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
    }

    public void executeSignatureAndHashAlgorithmsTestVectorsOriginalOrder() {
        if (certificateAlgorithm == null) {
            cannotTestSignatureAndHashAlgorithmsOriginalOrder();
            return;
        }

        SignatureAndHashAlgorithmTestVectors testVectors =
                new SignatureAndHashAlgorithmTestVectors(this, certificateAlgorithm);

        if (supportsConsecutiveOverlappingFragments()) {
            consecutiveSigAndHashTypeAOriginalOrder = testVectors.consecutiveTypeAOriginalOrder();
            consecutiveSigAndHashTypeBOriginalOrder = testVectors.consecutiveTypeBOriginalOrder();
        } else {
            consecutiveSigAndHashTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            consecutiveSigAndHashTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsSubsequentOverlappingFragments()) {
            subsequentSigAndHashTypeAOriginalOrder = testVectors.subsequentTypeAOriginalOrder();
            subsequentSigAndHashTypeBOriginalOrder = testVectors.subsequentTypeBOriginalOrder();
        } else {
            subsequentSigAndHashTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            subsequentSigAndHashTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsExtendedSubsequentOverlappingFragments()) {
            extendedSubsequentSigAndHashTypeAOriginalOrder =
                    testVectors.extendedSubsequentTypeAOriginalOrder();
            extendedSubsequentSigAndHashTypeBOriginalOrder =
                    testVectors.extendedSubsequentTypeBOriginalOrder();
        } else {
            extendedSubsequentSigAndHashTypeAOriginalOrder = TestResults.NOT_SUPPORTED;
            extendedSubsequentSigAndHashTypeBOriginalOrder = TestResults.NOT_SUPPORTED;
        }
    }

    private void cannotTestSignatureAndHashAlgorithmsOriginalOrder() {
        consecutiveSigAndHashTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        consecutiveSigAndHashTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
        subsequentSigAndHashTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        subsequentSigAndHashTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentSigAndHashTypeAOriginalOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentSigAndHashTypeBOriginalOrder = TestResults.CANNOT_BE_TESTED;
    }

    public void executeSignatureAndHashAlgorithmsTestVectorsReversedOrder() {
        if (certificateAlgorithm == null) {
            cannotTestSignatureAndHashAlgorithmsReversedOrder();
            return;
        }

        SignatureAndHashAlgorithmTestVectors testVectors =
                new SignatureAndHashAlgorithmTestVectors(this, certificateAlgorithm);

        if (supportsConsecutiveOverlappingFragments()) {
            consecutiveSigAndHashTypeAReversedOrder = testVectors.consecutiveTypeAReversedOrder();
            consecutiveSigAndHashTypeBReversedOrder = testVectors.consecutiveTypeBReversedOrder();
        } else {
            consecutiveSigAndHashTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            consecutiveSigAndHashTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsSubsequentOverlappingFragments()) {
            subsequentSigAndHashTypeAReversedOrder = testVectors.subsequentTypeAReversedOrder();
            subsequentSigAndHashTypeBReversedOrder = testVectors.subsequentTypeBReversedOrder();
        } else {
            subsequentSigAndHashTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            subsequentSigAndHashTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }

        if (supportsExtendedSubsequentOverlappingFragments()) {
            extendedSubsequentSigAndHashTypeAReversedOrder =
                    testVectors.extendedSubsequentTypeAReversedOrder();
            extendedSubsequentSigAndHashTypeBReversedOrder =
                    testVectors.extendedSubsequentTypeBReversedOrder();
        } else {
            extendedSubsequentSigAndHashTypeAReversedOrder = TestResults.NOT_SUPPORTED;
            extendedSubsequentSigAndHashTypeBReversedOrder = TestResults.NOT_SUPPORTED;
        }
    }

    private void cannotTestSignatureAndHashAlgorithmsReversedOrder() {
        consecutiveSigAndHashTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        consecutiveSigAndHashTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
        subsequentSigAndHashTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        subsequentSigAndHashTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentSigAndHashTypeAReversedOrder = TestResults.CANNOT_BE_TESTED;
        extendedSubsequentSigAndHashTypeBReversedOrder = TestResults.CANNOT_BE_TESTED;
    }

    public void executeClientKeyExchangeTestVectorsOriginalOrder() {
        ClientKeyExchangeTestVectors clientKeyExchangeTestVectors =
                new ClientKeyExchangeTestVectors(this, supportedCipherSuites);

        rsaClientKeyExchangeOriginalOrder =
                clientKeyExchangeTestVectors.rsaKeyExchangeOriginalOrder();
        dhClientKeyExchangeOriginalOrder =
                clientKeyExchangeTestVectors.dhKeyExchangeOriginalOrder();
        ecdhClientKeyExchangeOriginalOrder =
                clientKeyExchangeTestVectors.ecdhKeyExchangeOriginalOrder();
    }

    public void executeClientKeyExchangeTestVectorsReversedOrder() {
        ClientKeyExchangeTestVectors clientKeyExchangeTestVectors =
                new ClientKeyExchangeTestVectors(this, supportedCipherSuites);

        rsaClientKeyExchangeReversedOrder =
                clientKeyExchangeTestVectors.rsaKeyExchangeReversedOrder();
        dhClientKeyExchangeReversedOrder =
                clientKeyExchangeTestVectors.dhKeyExchangeReversedOrder();
        // ecdhClientKeyExchangeReversedOrder =
        //        clientKeyExchangeTestVectors.ecdhKeyExchangeReversedOrder();
    }

    private void cannotTestClientKeyExchange() {
        rsaClientKeyExchangeOriginalOrder = TestResults.CANNOT_BE_TESTED;
        rsaClientKeyExchangeReversedOrder = TestResults.CANNOT_BE_TESTED;
        dhClientKeyExchangeOriginalOrder = TestResults.CANNOT_BE_TESTED;
        dhClientKeyExchangeReversedOrder = TestResults.CANNOT_BE_TESTED;
        ecdhClientKeyExchangeOriginalOrder = TestResults.CANNOT_BE_TESTED;
        ecdhClientKeyExchangeReversedOrder = TestResults.CANNOT_BE_TESTED;
    }

    public AnalysisResults executeAnalysis(AnalysisConfig analysisConfig)
            throws OverlappingFragmentException {
        AbstractAnalysis analysis =
                OverlappingFragmentAnalysis.getOverlappingFragmentAnalysis(analysisConfig);
        analysis.initializeWorkflowTrace();

        State state = analysis.getState();
        executeState(state);

        return analysis.analyzeResults();
    }

    private boolean supportsConsecutiveOverlappingFragments() {
        return acceptsClientHelloConsecutiveFragments == TestResults.TRUE
                || acceptsClientKeyExchangeConsecutiveFragments == TestResults.TRUE;
    }

    private boolean supportsSubsequentOverlappingFragments() {
        return acceptsClientHelloSubsequentFragments == TestResults.TRUE
                || acceptsClientKeyExchangeSubsequentFragments == TestResults.TRUE;
    }

    private boolean supportsExtendedSubsequentOverlappingFragments() {
        return acceptsClientHelloExtendedSubsequentFragments == TestResults.TRUE
                || acceptsClientKeyExchangeExtendedSubsequentFragments == TestResults.TRUE;
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportsCookieExchange = report.getCookieExchange();
        requiresClientAuthentication = report.getClientAuthentication();

        supportedProtocolVersions = report.getSupportedProtocolVersions();
        supportedCipherSuites = new ArrayList<>(report.getSupportedCipherSuites());
        certificateAlgorithm = report.getSignatureAndHashAlgorithmCertificate();
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.PROTOCOL_VERSION)
                .and(
                        new ProbeRequirement<ServerReport>(TlsProbeType.CIPHER_SUITE)
                                .and(new ProbeRequirement<>(TlsProbeType.DTLS_HELLO_VERIFY_REQUEST))
                                .and(new ProbeRequirement<>(TlsProbeType.CLIENT_AUTHENTICATION))
                                .and(
                                        new ProbeRequirement<>(
                                                TlsProbeType
                                                        .SIGNATURE_AND_HASH_ALGORITHM_CERTIFICATE)))
                .and(new ProtocolTypeTrueRequirement<>(ProtocolType.DTLS));
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_CONSECUTIVE_FRAGMENTS,
                acceptsClientHelloConsecutiveFragments);
        put(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_CONSECUTIVE_FRAGMENTS,
                acceptsClientHelloConsecutiveFragments);
        put(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_SUBSEQUENT_FRAGMENTS,
                acceptsClientHelloSubsequentFragments);
        put(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_HELLO_EXTENDED_SUBSEQUENT_FRAGMENTS,
                acceptsClientHelloExtendedSubsequentFragments);

        put(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_CONSECUTIVE_FRAGMENTS,
                acceptsClientKeyExchangeConsecutiveFragments);
        put(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_SUBSEQUENT_FRAGMENTS,
                acceptsClientKeyExchangeSubsequentFragments);
        put(
                TlsAnalyzedProperty.ACCEPTS_CLIENT_KEY_EXCHANGE_EXTENDED_SUBSEQUENT_FRAGMENTS,
                acceptsClientKeyExchangeExtendedSubsequentFragments);

        // Version
        put(
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_A_ORIGINAL_ORDER,
                consecutiveVersionTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_B_ORIGINAL_ORDER,
                consecutiveVersionTypeBOriginalOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_A_ORIGINAL_ORDER,
                subsequentVersionTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_B_ORIGINAL_ORDER,
                subsequentVersionTypeBOriginalOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_A_ORIGINAL_ORDER,
                extendedSubsequentVersionTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_B_ORIGINAL_ORDER,
                extendedSubsequentVersionTypeBOriginalOrder);

        put(
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_A_REVERSED_ORDER,
                consecutiveVersionTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.CONSECUTIVE_VERSION_TYPE_B_REVERSED_ORDER,
                consecutiveVersionTypeBReversedOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_A_REVERSED_ORDER,
                subsequentVersionTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_VERSION_TYPE_B_REVERSED_ORDER,
                subsequentVersionTypeBReversedOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_A_REVERSED_ORDER,
                extendedSubsequentVersionTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_VERSION_TYPE_B_REVERSED_ORDER,
                extendedSubsequentVersionTypeBReversedOrder);

        // CipherSuites
        put(
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER,
                consecutiveCipherSuitesTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER,
                consecutiveCipherSuitesTypeBOriginalOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER,
                subsequentCipherSuitesTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER,
                subsequentCipherSuitesTypeBOriginalOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_A_ORIGINAL_ORDER,
                extendedSubsequentCipherSuitesTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_B_ORIGINAL_ORDER,
                extendedSubsequentCipherSuitesTypeBOriginalOrder);

        put(
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_A_REVERSED_ORDER,
                consecutiveCipherSuitesTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.CONSECUTIVE_CIPHER_SUITES_TYPE_B_REVERSED_ORDER,
                consecutiveCipherSuitesTypeBReversedOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_A_REVERSED_ORDER,
                subsequentCipherSuitesTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_CIPHER_SUITES_TYPE_B_REVERSED_ORDER,
                subsequentCipherSuitesTypeBReversedOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_A_REVERSED_ORDER,
                extendedSubsequentCipherSuitesTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_CIPHER_SUITES_TYPE_B_REVERSED_ORDER,
                extendedSubsequentCipherSuitesTypeBReversedOrder);

        // SignatureAndHashAlgorithms
        put(
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER,
                consecutiveSigAndHashTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER,
                consecutiveSigAndHashTypeBOriginalOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER,
                subsequentSigAndHashTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER,
                subsequentSigAndHashTypeBOriginalOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_A_ORIGINAL_ORDER,
                extendedSubsequentSigAndHashTypeAOriginalOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_B_ORIGINAL_ORDER,
                extendedSubsequentSigAndHashTypeBOriginalOrder);

        put(
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_A_REVERSED_ORDER,
                consecutiveSigAndHashTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.CONSECUTIVE_SIG_AND_HASH_TYPE_B_REVERSED_ORDER,
                consecutiveSigAndHashTypeBReversedOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_A_REVERSED_ORDER,
                subsequentSigAndHashTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.SUBSEQUENT_SIG_AND_HASH_TYPE_B_REVERSED_ORDER,
                subsequentSigAndHashTypeBReversedOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_A_REVERSED_ORDER,
                extendedSubsequentSigAndHashTypeAReversedOrder);
        put(
                TlsAnalyzedProperty.EXTENDED_SUBSEQUENT_SIG_AND_HASH_TYPE_B_REVERSED_ORDER,
                extendedSubsequentSigAndHashTypeBReversedOrder);

        // ClientKeyExchange
        put(
                TlsAnalyzedProperty.RSA_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER,
                rsaClientKeyExchangeOriginalOrder);
        put(
                TlsAnalyzedProperty.DH_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER,
                dhClientKeyExchangeOriginalOrder);
        put(
                TlsAnalyzedProperty.ECDH_CLIENT_KEY_EXCHANGE_ORIGINAL_ORDER,
                ecdhClientKeyExchangeOriginalOrder);

        put(
                TlsAnalyzedProperty.RSA_CLIENT_KEY_EXCHANGE_REVERSED_ORDER,
                rsaClientKeyExchangeReversedOrder);
        put(
                TlsAnalyzedProperty.DH_CLIENT_KEY_EXCHANGE_REVERSED_ORDER,
                dhClientKeyExchangeReversedOrder);
        put(
                TlsAnalyzedProperty.ECDH_CLIENT_KEY_EXCHANGE_REVERSED_ORDER,
                ecdhClientKeyExchangeReversedOrder);
    }
}
