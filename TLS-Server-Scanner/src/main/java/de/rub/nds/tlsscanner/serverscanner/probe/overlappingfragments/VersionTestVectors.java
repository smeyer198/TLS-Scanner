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
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsscanner.serverscanner.probe.DtlsOverlappingFragmentsProbe;
import de.upb.cs.analysis.AnalysisResults;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.analysis.Utils;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.OffsetConfig;
import de.upb.cs.config.OverrideConfig;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionTestVectors {

    private static final Logger LOGGER = LogManager.getLogger();
    private final DtlsOverlappingFragmentsProbe probe;

    private enum Combination implements TestResult {
        ORIGINAL_DIGEST_ORIGINAL_BYTES,
        ORIGINAL_DIGEST_OVERLAPPING_BYTES,
        UPDATED_DIGEST_ORIGINAL_BYTES,
        UPDATED_DIGEST_OVERLAPPING_BYTES,
        NO_VALID_COMBINATION,
        FATAL_PROTOCOL_VERSION,
    }

    public VersionTestVectors(DtlsOverlappingFragmentsProbe probe) {
        this.probe = probe;
    }

    public Optional<ProtocolVersion> getHighestProtocolVersion(
            List<ProtocolVersion> supportedVersions) {
        if (supportedVersions.contains(ProtocolVersion.DTLS12)) {
            return Optional.of(ProtocolVersion.DTLS12);
        }

        if (supportedVersions.contains(ProtocolVersion.DTLS10)) {
            return Optional.of(ProtocolVersion.DTLS10);
        }

        return Optional.empty();
    }

    public TestResult consecutiveTypeAOriginalOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(2, Field.VERSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.VERSION));
        fragment2.setPrependBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type A version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeAReversedOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(2, Field.VERSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.VERSION));
        fragment2.setPrependBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type A version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeBOriginalOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(1, Field.VERSION));
        fragment1.setAppendBytes(overlappingByte);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type B version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeBReversedOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(1, Field.VERSION));
        fragment1.setAppendBytes(overlappingByte);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type B version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeAOriginalOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type A version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeAReversedOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type A version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeBOriginalOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.VERSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type B version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeBReversedOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.VERSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type B version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeAOriginalOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type A version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeAReversedOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type A version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeBOriginalOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.VERSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type B version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeBReversedOrder(ProtocolVersion highestProtocolVersion) {
        ProtocolVersion targetVersion = getTargetProtocolVersion(highestProtocolVersion);
        String overlappingByte = Utils.bytesToHexString(new byte[] {targetVersion.getMinor()});

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloVersion(highestProtocolVersion);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.VERSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.VERSION));
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig, targetVersion);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type B version", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private ProtocolVersion getTargetProtocolVersion(ProtocolVersion highestProtocolVersion) {
        if (highestProtocolVersion == ProtocolVersion.DTLS12) {
            return ProtocolVersion.DTLS10;
        } else {
            return ProtocolVersion.DTLS12;
        }
    }

    private TestResult performAnalysis(AnalysisConfig analysisConfig, ProtocolVersion targetVersion)
            throws OverlappingFragmentException {
        // Original bytes in digest
        analysisConfig.setOverlappingBytesInDigest(false);
        AnalysisResults originalBytes = probe.executeAnalysis(analysisConfig);

        if (originalBytes.receivedFinishedMessage()) {
            if (originalBytes.getSelectedVersion().equals(targetVersion)) {
                return Combination.ORIGINAL_DIGEST_OVERLAPPING_BYTES;
            } else {
                return Combination.ORIGINAL_DIGEST_ORIGINAL_BYTES;
            }
        }

        // Updated bytes in digest
        analysisConfig.setOverlappingBytesInDigest(true);
        AnalysisResults updatedBytes = probe.executeAnalysis(analysisConfig);

        if (updatedBytes.receivedFinishedMessage()) {
            if (updatedBytes.getSelectedVersion().equals(targetVersion)) {
                return Combination.UPDATED_DIGEST_OVERLAPPING_BYTES;
            } else {
                return Combination.UPDATED_DIGEST_ORIGINAL_BYTES;
            }
        }

        if (checkForFatalProtocolVersion(originalBytes)
                || checkForFatalProtocolVersion(updatedBytes)) {
            return Combination.FATAL_PROTOCOL_VERSION;
        }

        return Combination.NO_VALID_COMBINATION;
    }

    private boolean checkForFatalProtocolVersion(AnalysisResults results) {
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

            if (alertMessage
                    .getDescription()
                    .getValue()
                    .equals(AlertDescription.PROTOCOL_VERSION.getValue())) {
                return true;
            }
        }
        return false;
    }
}
