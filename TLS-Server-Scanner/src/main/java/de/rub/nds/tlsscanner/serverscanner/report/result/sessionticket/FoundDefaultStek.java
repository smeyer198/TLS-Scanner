/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket;

import java.io.Serializable;

import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketEncryptionFormat;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.TicketEncryptionAlgorithm;

public class FoundDefaultStek implements Serializable {
    public final TicketEncryptionAlgorithm algorithm;
    public final SessionTicketEncryptionFormat format;
    public final byte[] key;
    public final PossibleSecret secret;

    public FoundDefaultStek(TicketEncryptionAlgorithm algorithm, SessionTicketEncryptionFormat format, byte[] key,
        PossibleSecret secret) {
        this.algorithm = algorithm;
        this.format = format;
        this.key = key;
        this.secret = secret;
    }

}
