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
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsOverlappingFragmentsProbe;
import de.upb.cs.analysis.AnalysisResults;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.analysis.Utils;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.MessageType;
import de.upb.cs.config.OffsetConfig;
import de.upb.cs.config.OverrideConfig;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAndHashAlgorithmTestVectors {

    private static final Logger LOGGER = LogManager.getLogger();

    // Finished MAC Bytes + Interpreted Bytes
    private enum Combination implements TestResult {
        ORIGINAL_DIGEST_ORIGINAL_BYTES,
        ORIGINAL_DIGEST_OVERLAPPING_BYTES,
        UPDATED_DIGEST_ORIGINAL_BYTES,
        UPDATED_DIGEST_OVERLAPPING_BYTES,
        FATAL_ALERT,
        NO_VALID_COMBINATION,
        NO_SUITABLE_ALGORITHM,
    }

    private final DtlsOverlappingFragmentsProbe probe;
    private final SignatureAndHashAlgorithm certificateAlgorithm;

    private final SignatureAndHashAlgorithm defaultRsaAlgorithm =
            SignatureAndHashAlgorithm.RSA_SHA256;
    private final SignatureAndHashAlgorithm defaultDsaAlgorithm =
            SignatureAndHashAlgorithm.DSA_SHA256;
    private final SignatureAndHashAlgorithm defaultEcdsaAlgorithm =
            SignatureAndHashAlgorithm.ECDSA_SHA256;

    public SignatureAndHashAlgorithmTestVectors(
            DtlsOverlappingFragmentsProbe probe, SignatureAndHashAlgorithm certificateAlgorithm) {
        this.probe = probe;
        this.certificateAlgorithm = certificateAlgorithm;
    }

    public void testForBasicExtensionSupport() {
        SignatureAndHashAlgorithm differentSignatureAlgorithm = getSignatureAndHashAlgorithm();

        if (differentSignatureAlgorithm == null) {
            return;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        // Use the algorithm that is different from the initial certificate
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                List.of(differentSignatureAlgorithm));
        analysisConfig.setMessageType(MessageType.NONE);
    }

    public TestResult consecutiveTypeAOriginalOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(2, Field.EXTENSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.EXTENSION));
        fragment2.setPrependBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeAReversedOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(2, Field.EXTENSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.EXTENSION));
        fragment2.setPrependBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeBOriginalOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(1, Field.EXTENSION));
        fragment1.setAppendBytes(overlappingByte);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeBReversedOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(1, Field.EXTENSION));
        fragment1.setAppendBytes(overlappingByte);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeAOriginalOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeAReversedOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeBOriginalOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.EXTENSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type B extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeBReversedOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.EXTENSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type B extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeAOriginalOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeAReversedOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeBOriginalOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.EXTENSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type A extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeBReversedOrder() {
        SignatureAndHashAlgorithm algorithmToOverride = getSignatureAndHashAlgorithm();

        if (algorithmToOverride == null) {
            return Combination.NO_SUITABLE_ALGORITHM;
        }

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(ProtocolVersion.DTLS12);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(
                Collections.singletonList(certificateAlgorithm));
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {algorithmToOverride.getByteValue()[1]});

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.EXTENSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.EXTENSION));
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type B extension", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult performAnalysis(AnalysisConfig analysisConfig)
            throws OverlappingFragmentException {
        // Original bytes in digest
        analysisConfig.setOverlappingBytesInDigest(false);
        AnalysisResults originalBytes = probe.executeAnalysis(analysisConfig);

        if (originalBytes.receivedFinishedMessage()) {
            SignatureAndHashAlgorithm algorithm =
                    originalBytes.getSelectedSignatureAndHashAlgorithm();

            // Same signature => Original Bytes
            if (certificateAlgorithm
                    .getSignatureAlgorithm()
                    .equals(algorithm.getSignatureAlgorithm())) {
                return Combination.ORIGINAL_DIGEST_ORIGINAL_BYTES;
            } else {
                // Different certificate => Interpreted overlapping byte
                probe.put(TlsAnalyzedProperty.HAS_MULTIPLE_CERTIFICATES, TestResults.TRUE);
                return Combination.ORIGINAL_DIGEST_OVERLAPPING_BYTES;
            }
        }

        // Overlapping bytes in digest
        analysisConfig.setOverlappingBytesInDigest(true);
        AnalysisResults manipulatedBytes = probe.executeAnalysis(analysisConfig);

        if (manipulatedBytes.receivedFinishedMessage()) {
            SignatureAndHashAlgorithm algorithm =
                    manipulatedBytes.getSelectedSignatureAndHashAlgorithm();

            if (certificateAlgorithm
                    .getSignatureAlgorithm()
                    .equals(algorithm.getSignatureAlgorithm())) {
                // Got original certificate, but digest over injected byte
                return Combination.UPDATED_DIGEST_ORIGINAL_BYTES;
            } else {
                // There is a second certificate, but the Finished message is computed correctly
                probe.put(TlsAnalyzedProperty.HAS_MULTIPLE_CERTIFICATES, TestResults.TRUE);
                return Combination.UPDATED_DIGEST_OVERLAPPING_BYTES;
            }
        }

        if (checkForFatalAlert(originalBytes) || checkForFatalAlert(manipulatedBytes)) {
            return Combination.FATAL_ALERT;
        }

        return Combination.NO_VALID_COMBINATION;
    }

    private boolean checkForFatalAlert(AnalysisResults results) {
        TlsAction tlsAction = results.getFirstFailedMessageAction();

        if (!(tlsAction instanceof MessageAction)) {
            return false;
        }

        MessageAction messageAction = (MessageAction) tlsAction;

        for (ProtocolMessage<?> message : messageAction.getMessages()) {
            if (!(message instanceof AlertMessage)) {
                continue;
            }

            AlertMessage alertMessage = (AlertMessage) message;

            if (alertMessage.getLevel().getValue().equals(AlertLevel.FATAL.getValue())) {
                return true;
            }
        }
        return false;
    }

    private SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        if (certificateAlgorithm.name().contains("RSA")) {
            return defaultEcdsaAlgorithm;
        }

        if (certificateAlgorithm.name().contains("ECDSA")) {
            return defaultDsaAlgorithm;
        }

        if (certificateAlgorithm.name().contains("DSA")) {
            return defaultRsaAlgorithm;
        }

        return null;
    }
}
