/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import com.google.common.base.Joiner;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.ConditionalGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;

public class HashAlgorithmsGuidelineCheck extends ConditionalGuidelineCheck {

    private List<HashAlgorithm> algorithms;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateStatus(SiteReport report) {
        if (report.getSupportedSignatureAndHashAlgorithms() == null) {
            return Pair.of(GuidelineCheckStatus.UNCERTAIN, "Site Report is missing supported algorithms.");
        }
        List<HashAlgorithm> nonRecommended = new ArrayList<>();
        for (SignatureAndHashAlgorithm alg : report.getSupportedSignatureAndHashAlgorithms()) {
            if (!this.algorithms.contains(alg.getHashAlgorithm())) {
                nonRecommended.add(alg.getHashAlgorithm());
            }
        }
        if (nonRecommended.isEmpty()) {
            return Pair.of(GuidelineCheckStatus.PASSED, "Only listed hash algorithms are supported.");
        }
        return Pair.of(GuidelineCheckStatus.FAILED,
            "The following hash algorithms were supported but not recommended:\n"
                + Joiner.on('\n').join(nonRecommended));
    }

    public List<HashAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<HashAlgorithm> algorithms) {
        this.algorithms = algorithms;
    }
}
