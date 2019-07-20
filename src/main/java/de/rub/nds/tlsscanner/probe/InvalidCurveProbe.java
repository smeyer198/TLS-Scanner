/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.InvalidCurveResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class InvalidCurveProbe extends TlsProbe {

    private TestResult supportsEphemeral;

    private TestResult supportsStatic;

    public InvalidCurveProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.INVALID_CURVE, config, 10);
    }

    @Override
    public ProbeResult executeTest() {
        try {        
            Boolean vulnerableClassic = null;
            Boolean vulnerableEphemeral = null;
            if (supportsStatic == null || supportsStatic == null) {
                InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
                ClientDelegate delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
                delegate.setHost(getScannerConfig().getClientDelegate().getHost());
                StarttlsDelegate starttlsDelegate = (StarttlsDelegate) invalidCurveAttackConfig.getDelegate(StarttlsDelegate.class);
                starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
                InvalidCurveAttacker attacker = new InvalidCurveAttacker(invalidCurveAttackConfig, invalidCurveAttackConfig.createConfig());
                vulnerableClassic = attacker.isVulnerable();
            }
            if (supportsEphemeral == null || supportsEphemeral == null) {
                InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
                invalidCurveAttackConfig.setEphemeral(true);
                StarttlsDelegate starttlsDelegate = (StarttlsDelegate) invalidCurveAttackConfig.getDelegate(StarttlsDelegate.class);
                starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
                ClientDelegate delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
                delegate.setHost(getScannerConfig().getClientDelegate().getHost());
                InvalidCurveAttacker attacker = new InvalidCurveAttacker(invalidCurveAttackConfig, invalidCurveAttackConfig.createConfig());
                vulnerableEphemeral = attacker.isVulnerable();
            }
            if (!getScannerConfig().isImplementation()) {
                if (vulnerableClassic == null) {
                    vulnerableClassic = false;
                }
                if (vulnerableEphemeral == null) {
                    vulnerableEphemeral = false;
                }
            }
            return new InvalidCurveResult(vulnerableClassic == true ? TestResult.TRUE : TestResult.FALSE , vulnerableEphemeral == true ? TestResult.TRUE : TestResult.FALSE);
        } catch(Exception e) {
            return new InvalidCurveResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        } 
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_ECDH)  == TestResult.TRUE || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportsEphemeral = report.getResult(AnalyzedProperty.SUPPORTS_ECDH);
        supportsStatic = report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH);
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new InvalidCurveResult(TestResult.UNTESTED, TestResult.UNTESTED);
    }
}
