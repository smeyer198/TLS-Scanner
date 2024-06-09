/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.overlappingfragments;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsOverlappingFragmentsProbe;
import de.upb.cs.analysis.AnalysisResults;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.MessageType;
import de.upb.cs.config.OffsetConfig;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OverlappingFragmentSupport {

    private static final Logger LOGGER = LogManager.getLogger();
    private final DtlsOverlappingFragmentsProbe probe;

    public OverlappingFragmentSupport(DtlsOverlappingFragmentsProbe probe) {
        this.probe = probe;
    }

    public TestResult acceptsClientHelloConsecutiveFragments() {
        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(3, Field.CIPHER_SUITES));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.CIPHER_SUITES));

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return testOverlappingFragmentSupport(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing for consecutive fragment support", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult acceptsClientHelloSubsequentFragments() {
        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return testOverlappingFragmentSupport(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing for subsequent fragment support", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult acceptsClientHelloExtendedSubsequentFragments() {
        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return testOverlappingFragmentSupport(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing for extended subsequent fragment support in CH", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult acceptsClientKeyExchangeConsecutiveFragments(
            List<CipherSuite> supportedCipherSuites) {
        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        setMessageType(analysisConfig, supportedCipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(30);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffset(29);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return testOverlappingFragmentSupport(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing for consecutive fragment support in CKE", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult acceptsClientKeyExchangeSubsequentFragments(
            List<CipherSuite> supportedCipherSuites) {
        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        setMessageType(analysisConfig, supportedCipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffset(30);
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return testOverlappingFragmentSupport(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing for subsequent fragment support in CKE", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult acceptsClientKeyExchangeExtendedSubsequentFragments(
            List<CipherSuite> supportedCipherSuites) {
        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        setMessageType(analysisConfig, supportedCipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffset(30);
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return testOverlappingFragmentSupport(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing for extended subsequent fragment support in CKE", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private void setMessageType(
            AnalysisConfig analysisConfig, List<CipherSuite> supportedCipherSuites) {
        List<CipherSuite> cipherSuites = getRsaKeyExchangeCipherSuites(supportedCipherSuites);

        if (!cipherSuites.isEmpty()) {
            analysisConfig.setMessageType(MessageType.RSA_CLIENT_KEY_EXCHANGE);
            analysisConfig.setClientHelloCipherSuites(cipherSuites);
        } else {
            cipherSuites = getEcdhKeyExchangeCipherSuites(supportedCipherSuites);

            if (!cipherSuites.isEmpty()) {
                analysisConfig.setMessageType(MessageType.ECDH_CLIENT_KEY_EXCHANGE);
                analysisConfig.setClientHelloCipherSuites(cipherSuites);
            } else {
                cipherSuites = getDhKeyExchangeCipherSuites(supportedCipherSuites);

                if (!cipherSuites.isEmpty()) {
                    analysisConfig.setMessageType(MessageType.DH_CLIENT_KEY_EXCHANGE);
                    analysisConfig.setClientHelloCipherSuites(cipherSuites);
                }
            }
        }
    }

    private List<CipherSuite> getRsaKeyExchangeCipherSuites(
            List<CipherSuite> supportedCipherSuites) {
        List<CipherSuite> result = new ArrayList<>();

        for (CipherSuite cipherSuite : supportedCipherSuites) {
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);

            if (algorithm.isKeyExchangeRsa()) {
                result.add(cipherSuite);
            }
        }
        return result;
    }

    private List<CipherSuite> getDhKeyExchangeCipherSuites(
            List<CipherSuite> supportedCipherSuites) {
        List<CipherSuite> result = new ArrayList<>();

        for (CipherSuite cipherSuite : supportedCipherSuites) {
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);

            if (algorithm.isKeyExchangeDh()) {
                result.add(cipherSuite);
            }
        }
        return result;
    }

    private List<CipherSuite> getEcdhKeyExchangeCipherSuites(
            List<CipherSuite> supportedCipherSuites) {
        List<CipherSuite> result = new ArrayList<>();

        for (CipherSuite cipherSuite : supportedCipherSuites) {
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);

            if (algorithm.isKeyExchangeEcdh()) {
                result.add(cipherSuite);
            }
        }
        return result;
    }

    private TestResult testOverlappingFragmentSupport(AnalysisConfig analysisConfig)
            throws OverlappingFragmentException {
        AnalysisResults results = probe.executeAnalysis(analysisConfig);
        TestResult result;

        if (results.isReceivedServerHelloMessage()) {
            result = TestResults.TRUE;

            if (!results.receivedFinishedMessage()) {
                result = TestResults.PARTIALLY;
            }
        } else {
            result = TestResults.FALSE;
        }
        return result;
    }
}
