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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
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
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CipherSuiteTestVectors {

    private static final Logger LOGGER = LogManager.getLogger();

    // Finished MAC Bytes + Interpreted Bytes
    private enum Combination implements TestResult {
        ORIGINAL_DIGEST_ORIGINAL_BYTES,
        ORIGINAL_DIGEST_OVERLAPPING_BYTES,
        UPDATED_DIGEST_ORIGINAL_BYTES,
        UPDATED_DIGEST_OVERLAPPING_BYTES,
        NO_VALID_COMBINATION,
    }

    private final DtlsOverlappingFragmentsProbe probe;

    public CipherSuiteTestVectors(DtlsOverlappingFragmentsProbe probe) {
        this.probe = probe;
    }

    public Optional<CipherSuite> getPreferredCipherSuite(List<CipherSuite> potentialCipherSuites) {
        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setMessageType(MessageType.NONE);
        analysisConfig.setClientHelloCipherSuites(potentialCipherSuites);

        try {
            AnalysisResults results = probe.executeAnalysis(analysisConfig);
            CipherSuite selectedCipherSuite = results.getSelectedCipherSuite();

            if (selectedCipherSuite != null) {
                return Optional.of(selectedCipherSuite);
            }
        } catch (OverlappingFragmentException e) {
            LOGGER.info("Error while determining the preferred cipher suites", e);
        }

        return Optional.empty();
    }

    public List<CipherSuite> getSimilarCipherSuites(List<CipherSuite> supportedCipherSuites) {
        for (CipherSuite cipherSuite1 : supportedCipherSuites) {
            for (CipherSuite cipherSuite2 : supportedCipherSuites) {
                byte[] byteValue1 = cipherSuite1.getByteValue();
                byte[] byteValue2 = cipherSuite2.getByteValue();

                if (byteValue1[0] == byteValue2[0] && byteValue1[1] != byteValue2[1]) {
                    return Arrays.asList(cipherSuite1, cipherSuite2);
                }
            }
        }
        return Collections.emptyList();
    }

    public TestResult consecutiveTypeAOriginalOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(2, Field.CIPHER_SUITES));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.CIPHER_SUITES));
        fragment2.setPrependBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (OverlappingFragmentException e) {
            LOGGER.info("Error while testing consecutive type A cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeAReversedOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(2, Field.CIPHER_SUITES));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.CIPHER_SUITES));
        fragment2.setPrependBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (OverlappingFragmentException e) {
            LOGGER.info("Error while testing consecutive type A cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeBOriginalOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(1, Field.CIPHER_SUITES));
        fragment1.setAppendBytes(overlappingByte);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type B cipher suites");
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult consecutiveTypeBReversedOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(1, Field.CIPHER_SUITES));
        fragment1.setAppendBytes(overlappingByte);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing consecutive type B cipher suites");
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeAOriginalOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type A cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeAReversedOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type A cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeBOriginalOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.CIPHER_SUITES));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type B cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult subsequentTypeBReversedOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.CIPHER_SUITES));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing subsequent type B cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeAOriginalOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type A cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeAReversedOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(0);
        fragment2.setAppendBytes(overlappingByte);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type A cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeBOriginalOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.CIPHER_SUITES));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment1, fragment2, fragment3));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type B cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult extendedSubsequentTypeBReversedOrder(List<CipherSuite> cipherSuites) {
        String overlappingByte =
                Utils.bytesToHexString(new byte[] {cipherSuites.get(1).getByteValue()[1]});
        CipherSuite targetCipherSuite = cipherSuites.get(1);

        AnalysisConfig analysisConfig = probe.initializeAnalysisConfig();
        analysisConfig.setClientHelloCipherSuites(cipherSuites);

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLength(-1);
        fragment1.setOverrideConfig(new OverrideConfig(1, overlappingByte, Field.CIPHER_SUITES));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(1, Field.CIPHER_SUITES));
        fragment2.setLength(1);

        FragmentConfig fragment3 = new FragmentConfig();
        fragment3.setOffset(-1);

        analysisConfig.setFragments(Arrays.asList(fragment2, fragment1, fragment3));

        try {
            return performAnalysis(analysisConfig, targetCipherSuite);
        } catch (Exception e) {
            LOGGER.info("Error while testing extended subsequent type B cipher suites", e);
            return TestResults.ERROR_DURING_TEST;
        }
    }

    public TestResult performAnalysis(AnalysisConfig analysisConfig, CipherSuite targetCipherSuite)
            throws OverlappingFragmentException {
        // Original bytes in digest
        analysisConfig.setOverlappingBytesInDigest(false);
        AnalysisResults originalBytes = probe.executeAnalysis(analysisConfig);

        if (originalBytes.receivedFinishedMessage()) {
            if (originalBytes.getSelectedCipherSuite().equals(targetCipherSuite)) {
                return Combination.ORIGINAL_DIGEST_OVERLAPPING_BYTES;
            } else {
                return Combination.ORIGINAL_DIGEST_ORIGINAL_BYTES;
            }
        }

        // Updated bytes in digest
        analysisConfig.setOverlappingBytesInDigest(true);
        AnalysisResults updatedBytes = probe.executeAnalysis(analysisConfig);

        if (updatedBytes.receivedFinishedMessage()) {
            if (updatedBytes.getSelectedCipherSuite().equals(targetCipherSuite)) {
                return Combination.UPDATED_DIGEST_OVERLAPPING_BYTES;
            } else {
                return Combination.UPDATED_DIGEST_ORIGINAL_BYTES;
            }
        }

        return Combination.NO_VALID_COMBINATION;
    }
}
