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
import de.upb.cs.config.Constants;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.MessageType;
import de.upb.cs.config.OffsetConfig;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientKeyExchangeTestVectors {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String updatedDhPrivateKey = "FEFE";
    private static final String updatedEcPrivateKey = "5";

    private enum Combination implements TestResult {
        ORIGINAL_KEYS_ORIGINAL_BYTES,
        ORIGINAL_KEYS_OVERLAPPING_BYTES,
        UPDATED_KEYS_ORIGINAL_BYTES,
        UPDATED_KEYS_OVERLAPPING_BYTES,
        NOT_SUPPORTED,
        NO_VALID_COMBINATION,
    }

    private final DtlsOverlappingFragmentsProbe probe;
    private final List<CipherSuite> supportedCipherSuites;

    public ClientKeyExchangeTestVectors(
            DtlsOverlappingFragmentsProbe probe, List<CipherSuite> supportedCipherSuites) {
        this.probe = probe;
        this.supportedCipherSuites = supportedCipherSuites;
    }

    public TestResult rsaKeyExchangeOriginalOrder() {
        List<CipherSuite> rsaCipherSuites = supportsRsaKeyExchange();

        if (rsaCipherSuites.isEmpty()) {
            return Combination.NOT_SUPPORTED;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setMessageType(MessageType.RSA_CLIENT_KEY_EXCHANGE);
        analysisConfig.setClientHelloCipherSuites(rsaCipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(0, Field.PUBLIC_KEY));
        fragment2.setLength(0);
        fragment2.setAppendBytes(Constants.MANIPULATED_PUBLIC_KEY_LABEL);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(0);
        fragment3.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing RSA Key Exchange", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult rsaKeyExchangeReversedOrder() {
        List<CipherSuite> rsaCipherSuites = supportsRsaKeyExchange();

        if (rsaCipherSuites.isEmpty()) {
            return Combination.NOT_SUPPORTED;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setMessageType(MessageType.RSA_CLIENT_KEY_EXCHANGE);
        analysisConfig.setClientHelloCipherSuites(rsaCipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(0, Field.PUBLIC_KEY));
        fragment2.setLength(0);
        fragment2.setAppendBytes(Constants.MANIPULATED_PUBLIC_KEY_LABEL);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(0);
        fragment3.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing RSA Key Exchange", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult dhKeyExchangeOriginalOrder() {
        List<CipherSuite> dhCipherSuites = supportsDhKeyExchange();

        if (dhCipherSuites.isEmpty()) {
            return Combination.NOT_SUPPORTED;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setMessageType(MessageType.DH_CLIENT_KEY_EXCHANGE);
        analysisConfig.setClientHelloCipherSuites(dhCipherSuites);
        analysisConfig.setDhPrivateKey(updatedDhPrivateKey);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(0, Field.PUBLIC_KEY));
        fragment2.setLength(0);
        fragment2.setAppendBytes(Constants.MANIPULATED_PUBLIC_KEY_LABEL);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(0);
        fragment3.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing DH Key Exchange", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult dhKeyExchangeReversedOrder() {
        List<CipherSuite> dhCipherSuites = supportsDhKeyExchange();

        if (dhCipherSuites.isEmpty()) {
            return Combination.NOT_SUPPORTED;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setMessageType(MessageType.DH_CLIENT_KEY_EXCHANGE);
        analysisConfig.setClientHelloCipherSuites(dhCipherSuites);
        analysisConfig.setDhPrivateKey(updatedDhPrivateKey);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(0, Field.PUBLIC_KEY));
        fragment2.setLength(0);
        fragment2.setAppendBytes(Constants.MANIPULATED_PUBLIC_KEY_LABEL);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(0);
        fragment3.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing DH Key Exchange", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult ecdhKeyExchangeOriginalOrder() {
        List<CipherSuite> ecdhCipherSuites = supportsEcdhKeyExchange();

        if (ecdhCipherSuites.isEmpty()) {
            return Combination.NOT_SUPPORTED;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setMessageType(MessageType.ECDH_CLIENT_KEY_EXCHANGE);
        analysisConfig.setClientHelloCipherSuites(ecdhCipherSuites);
        analysisConfig.setEcPrivateKey(updatedEcPrivateKey);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(0, Field.PUBLIC_KEY));
        fragment2.setLength(0);
        fragment2.setAppendBytes(Constants.MANIPULATED_PUBLIC_KEY_LABEL);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(0);
        fragment3.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing ECDH KeyExchange", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult ecdhKeyExchangeReversedOrder() {
        List<CipherSuite> ecdhCipherSuites = supportsEcdhKeyExchange();

        if (ecdhCipherSuites.isEmpty()) {
            return Combination.NOT_SUPPORTED;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setMessageType(MessageType.ECDH_CLIENT_KEY_EXCHANGE);
        analysisConfig.setClientHelloCipherSuites(ecdhCipherSuites);
        analysisConfig.setEcPrivateKey(updatedEcPrivateKey);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(0, Field.PUBLIC_KEY));
        fragment2.setLength(0);
        fragment2.setAppendBytes(Constants.MANIPULATED_PUBLIC_KEY_LABEL);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(0);
        fragment3.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing ECDH KeyExchange", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult performAnalysis(AnalysisConfig analysisConfig)
            throws OverlappingFragmentException {
        // Original keys, original bytes
        analysisConfig.setUseUpdatedKeys(false);
        analysisConfig.setOverlappingBytesInDigest(false);
        AnalysisResults results1 = probe.executeAnalysis(analysisConfig);

        if (results1.receivedFinishedMessage()) {
            return Combination.ORIGINAL_KEYS_ORIGINAL_BYTES;
        }

        // Original keys, overlapping Bytes
        analysisConfig.setUseUpdatedKeys(false);
        analysisConfig.setOverlappingBytesInDigest(true);
        AnalysisResults results2 = probe.executeAnalysis(analysisConfig);

        if (results2.receivedFinishedMessage()) {
            return Combination.ORIGINAL_KEYS_OVERLAPPING_BYTES;
        }

        // Updated keys, original Bytes
        analysisConfig.setUseUpdatedKeys(true);
        analysisConfig.setOverlappingBytesInDigest(false);
        AnalysisResults results3 = probe.executeAnalysis(analysisConfig);

        if (results3.receivedFinishedMessage()) {
            return Combination.UPDATED_KEYS_ORIGINAL_BYTES;
        }

        // Updated keys, overlapping Bytes
        analysisConfig.setUseUpdatedKeys(true);
        analysisConfig.setOverlappingBytesInDigest(true);
        AnalysisResults results4 = probe.executeAnalysis(analysisConfig);

        if (results4.receivedFinishedMessage()) {
            return Combination.UPDATED_KEYS_OVERLAPPING_BYTES;
        }

        return Combination.NO_VALID_COMBINATION;
    }

    private List<CipherSuite> supportsRsaKeyExchange() {
        List<CipherSuite> result = new ArrayList<>();

        for (CipherSuite cipherSuite : supportedCipherSuites) {
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);

            if (algorithm.isKeyExchangeRsa()) {
                result.add(cipherSuite);
            }
        }
        return result;
    }

    private List<CipherSuite> supportsDhKeyExchange() {
        List<CipherSuite> result = new ArrayList<>();

        for (CipherSuite cipherSuite : supportedCipherSuites) {
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);

            if (algorithm.isKeyExchangeDh()) {
                result.add(cipherSuite);
            }
        }
        return result;
    }

    private List<CipherSuite> supportsEcdhKeyExchange() {
        List<CipherSuite> result = new ArrayList<>();

        for (CipherSuite cipherSuite : supportedCipherSuites) {
            KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);

            if (algorithm.isKeyExchangeEcdh()) {
                result.add(cipherSuite);
            }
        }
        return result;
    }
}
