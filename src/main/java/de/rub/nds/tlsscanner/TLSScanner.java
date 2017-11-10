/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.probe.BleichenbacherProbe;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteOrderProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.Cve20162107Probe;
import de.rub.nds.tlsscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.PoodleProbe;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.TLSProbe;
import de.rub.nds.tlsscanner.probe.TlsPoodleProbe;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSScanner {

    private final ScanJobExecutor executor;
    private final ScannerConfig config;

    public TLSScanner(String websiteHost, boolean attackingScans) {
        this.executor = new ScanJobExecutor(1);
        config = new ScannerConfig(new GeneralDelegate());
        config.getGeneralDelegate().setLogLevel(Level.WARN);
        ClientDelegate clientDelegate = (ClientDelegate) config.getDelegateList().get(1);
        clientDelegate.setHost(websiteHost);
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.WARN);
    }

    public TLSScanner(ScannerConfig config) {
        this.executor = new ScanJobExecutor(config.getThreads());
        this.config = config;
        if (config.getGeneralDelegate().getLogLevel() == Level.ALL) {
            Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.ALL);
            Configurator.setAllLevels("de.rub.nds.modifiablevariable", Level.ALL);

        } else if (config.getGeneralDelegate().getLogLevel() == Level.TRACE) {
            Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.INFO);
            Configurator.setAllLevels("de.rub.nds.modifiablevariable", Level.INFO);
        } else {
            Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.OFF);
            Configurator.setAllLevels("de.rub.nds.modifiablevariable", Level.OFF);
        }
    }

    public SiteReport scan() {
        List<TLSProbe> testList = new LinkedList<>();
        testList.add(new CertificateProbe(config));
        testList.add(new ProtocolVersionProbe(config));
        testList.add(new CiphersuiteProbe(config));
        testList.add(new CiphersuiteOrderProbe(config));
        testList.add(new HeartbleedProbe(config));
        // testList.add(new NamedCurvesProbe(websiteHost));
        testList.add(new PaddingOracleProbe(config));
        testList.add(new BleichenbacherProbe(config));
        testList.add(new PoodleProbe(config));
        testList.add(new TlsPoodleProbe(config));
        testList.add(new Cve20162107Probe(config));
        testList.add(new InvalidCurveProbe(config));
        
        // testList.add(new SignatureAndHashAlgorithmProbe(websiteHost));
        ScanJob job = new ScanJob(testList);
        return executor.execute(config, job);
    }

}
