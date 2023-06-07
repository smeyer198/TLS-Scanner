/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.StatsWriter;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.AlpacaResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

public abstract class TlsProbe implements Callable<ProbeResult> {

    protected static final Logger LOGGER = LogManager.getLogger(TlsProbe.class.getName());

    protected final ScannerConfig scannerConfig;
    protected final ProbeType type;

    private final ParallelExecutor parallelExecutor;

    private final StatsWriter writer;

    private AtomicBoolean readyForExecution = new AtomicBoolean(false);

    public TlsProbe(ParallelExecutor parallelExecutor, ProbeType type, ScannerConfig scannerConfig) {
        this.scannerConfig = scannerConfig;
        this.type = type;
        this.parallelExecutor = parallelExecutor;
        this.writer = new StatsWriter();
    }

    public final ScannerConfig getScannerConfig() {
        return scannerConfig;
    }

    public String getProbeName() {
        return type.name();
    }

    public ProbeType getType() {
        return type;
    }

    @Override
    public ProbeResult call() {
        ThreadContext.put("host",
            this.scannerConfig.getClientDelegate().getSniHostname() == null
                ? this.scannerConfig.getClientDelegate().getHost()
                : this.scannerConfig.getClientDelegate().getSniHostname());
        LOGGER.debug("Executing:" + getProbeName());
        long startTime = System.currentTimeMillis();

        ProbeResult result = null;
        try {
            result = executeTest();
        } catch (Exception e) {
            // InterruptedException are wrapped in the ParallelExceutor of Tls-Attacker so we unwrap them here
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
            } else {
                LOGGER.error("Could not scan for " + getProbeName(), e);
            }
            result = getCouldNotExecuteResult();
        } finally {
            long stopTime = System.currentTimeMillis();
            if (result != null) {
                result.setStartTime(startTime);
                result.setStopTime(stopTime);
            } else {
                LOGGER.warn("" + getProbeName() + " - is null result");
            }
            LOGGER.debug("Finished " + getProbeName() + " -  Took " + (stopTime - startTime) / 1000 + "s");
            ThreadContext.remove("host");
        }
        return result;
    }

    public final void executeState(State... states) {
        this.executeState(new ArrayList<State>(Arrays.asList(states)));

    }

    public final void executeState(Iterable<State> states) {
        parallelExecutor.bulkExecuteStateTasks(states);
        for (State state : states) {
            writer.extract(state);
        }

    }

    public abstract ProbeResult executeTest();

    public void executeAndMerge(SiteReport report) {
        ProbeResult result = this.call();
        result.merge(report);
    }

    public abstract boolean canBeExecuted(SiteReport report);

    public abstract ProbeResult getCouldNotExecuteResult();

    public abstract void adjustConfig(SiteReport report);

    public ParallelExecutor getParallelExecutor() {
        return parallelExecutor;
    }

    public StatsWriter getWriter() {
        return writer;
    }

    public AtomicBoolean getReadyForExecution() {
        return readyForExecution;
    }

}
