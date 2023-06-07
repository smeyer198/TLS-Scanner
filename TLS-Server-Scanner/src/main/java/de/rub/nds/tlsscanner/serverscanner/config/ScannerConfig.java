/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.serverscanner.config.delegate.DtlsDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsscanner.serverscanner.config.delegate.CallbackDelegate;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import org.bouncycastle.util.IPAddress;

import java.util.Arrays;
import java.util.List;

public class ScannerConfig extends TLSDelegateConfig {

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @Parameter(names = "-parallelProbes", required = false,
        description = "Defines the number of threads responsible for different TLS probes. If set to 1, only one specific TLS probe (e.g., TLS version scan) can be run in time.")
    private int parallelProbes = 1;

    @Parameter(names = "-noColor", required = false, description = "If you use Windows or don't want colored text.")
    private boolean noColor = false;

    @Parameter(names = "-scanDetail", required = false, description = "How detailed do you want to scan?")
    private ScannerDetail scanDetail = ScannerDetail.NORMAL;

    @Parameter(names = "-reportDetail", required = false, description = "How detailed do you want the report to be?")
    private ScannerDetail reportDetail = ScannerDetail.NORMAL;

    @Parameter(names = "-applicationProtocol", required = false,
        description = "Which application data protocol the server is running.")
    private ApplicationProtocol applicationProtocol = ApplicationProtocol.HTTP;

    @Parameter(names = "-threads", required = false,
        description = "The maximum number of threads used to execute TLS probes located in the scanning queue. This is also the maximum number of threads communicating with the analyzed server.")
    private int overallThreads = 1;

    @Parameter(names = "-timeout", required = false,
        description = "The timeout used for the scans in ms (default 1000)")
    private int timeout = 1000;

    @Parameter(names = "-connectionTimeout", required = false,
        description = "The connection timeout used for the scans in ms (default 8000)")
    private int connectionTimeout = 8000;

    @Parameter(names = "-additionalRandomCollection", required = false,
        description = "Number of connections that should be additionally performed to collect more randomness data to get more accurate analysis")
    private int additionalRandomnessHandshakes = 0;

    @Parameter(names = "-probeTimeout", required = false,
        description = "The timeout for each probe in ms (default 1800000)")
    private int probeTimeout = 1800000;

    @ParametersDelegate
    private CcaDelegate ccaDelegate;

    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    @ParametersDelegate
    private DtlsDelegate dtlsDelegate;

    @ParametersDelegate
    private CallbackDelegate callbackDelegate;

    private List<ProbeType> probes = null;

    private Config baseConfig = null;

    public ScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        this.dtlsDelegate = new DtlsDelegate();
        this.clientDelegate = new ClientDelegate();
        this.starttlsDelegate = new StarttlsDelegate();
        this.ccaDelegate = new CcaDelegate();
        this.callbackDelegate = new CallbackDelegate();

        addDelegate(clientDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(ccaDelegate);
        addDelegate(dtlsDelegate);
        addDelegate(callbackDelegate);
    }

    public ScannerConfig(GeneralDelegate delegate, ClientDelegate clientDelegate) {
        super(delegate);
        this.clientDelegate = clientDelegate;
        this.dtlsDelegate = new DtlsDelegate();
        this.starttlsDelegate = new StarttlsDelegate();
        this.ccaDelegate = new CcaDelegate();
        this.callbackDelegate = new CallbackDelegate();

        addDelegate(clientDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(ccaDelegate);
        addDelegate(dtlsDelegate);
        addDelegate(callbackDelegate);
    }

    public ApplicationProtocol getApplicationProtocol() {
        return applicationProtocol;
    }

    public void setApplicationProtocol(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public int getOverallThreads() {
        return overallThreads;
    }

    public void setOverallThreads(int overallThreads) {
        this.overallThreads = overallThreads;
    }

    public int getParallelProbes() {
        return parallelProbes;
    }

    public void setParallelProbes(int parallelProbes) {
        this.parallelProbes = parallelProbes;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public StarttlsDelegate getStarttlsDelegate() {
        return starttlsDelegate;
    }

    public DtlsDelegate getDtlsDelegate() {
        return dtlsDelegate;
    }

    public CcaDelegate getCcaDelegate() {
        return ccaDelegate;
    }

    public CallbackDelegate getCallbackDelegate() {
        return callbackDelegate;
    }

    public boolean isNoColor() {
        return noColor;
    }

    public void setNoColor(boolean noColor) {
        this.noColor = noColor;
    }

    public ScannerDetail getScanDetail() {
        return scanDetail;
    }

    public void setScanDetail(ScannerDetail scanDetail) {
        this.scanDetail = scanDetail;
    }

    public ScannerDetail getReportDetail() {
        return reportDetail;
    }

    public void setReportDetail(ScannerDetail reportDetail) {
        this.reportDetail = reportDetail;
    }

    public int getAdditionalRandomnessHandshakes() {
        return additionalRandomnessHandshakes;
    }

    public void setAdditionalRandomnessHandshakes(int additionalRandomnessHandshakes) {
        this.additionalRandomnessHandshakes = additionalRandomnessHandshakes;
    }

    @Override
    public Config createConfig() {
        if (baseConfig != null) {
            return baseConfig.createCopy();
        }

        Config config = super.createConfig(Config.createConfig());
        if (!IPAddress.isValid(config.getDefaultClientConnection().getHostname())
            || clientDelegate.getSniHostname() != null) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }

        config.getDefaultClientConnection().setTimeout(timeout);
        if (timeout > AliasedConnection.DEFAULT_FIRST_TIMEOUT) {
            config.getDefaultClientConnection().setFirstTimeout(timeout);
        }

        config.getDefaultClientConnection().setConnectionTimeout(connectionTimeout);
        return config;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    public Config getBaseConfig() {
        return baseConfig;
    }

    public void setBaseConfig(Config baseConfig) {
        this.baseConfig = baseConfig;
    }

    public List<ProbeType> getProbes() {
        return probes;
    }

    public void setProbes(List<ProbeType> probes) {
        this.probes = probes;
    }

    public void setProbes(ProbeType... probes) {
        this.probes = Arrays.asList(probes);
    }

    public int getProbeTimeout() {
        return probeTimeout;
    }

    public void setProbeTimeout(int probeTimeout) {
        this.probeTimeout = probeTimeout;
    }
}
