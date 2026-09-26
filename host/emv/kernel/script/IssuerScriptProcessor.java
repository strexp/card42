package card42.host.emv.kernel.script;

import card42.host.emv.lib.Terminal;

import java.io.ByteArrayOutputStream;

import javax.smartcardio.ResponseAPDU;

import card42.host.emv.crypto.SmCrypto;

/**
 * Terminal-side issuer script processing (EMV v4.4 Book 3 §10.10, EMV v4.4
 * Book 4 §6.3.9 / Annex A5).
 *
 * <p>Given one or more 71/72 Issuer Script templates it parses the Script
 * Identifier and the 86 Issuer Script Commands, sends each command to the card,
 * and aggregates the Issuer Script Results (tag 9F5B): byte 1 = (result &lt;&lt; 4)
 * | sequence of the failing command, bytes 2-5 = the Script Identifier.
 *
 * <p>The caller applies the result to the TVR: a failure before the final
 * GENERATE AC sets TVR byte 5 b6, after it b5 (EMV v4.4 Book 3 Annex C §C5).
 */
public final class IssuerScriptProcessor {

    /** Aggregated outcome of processing one or more issuer scripts. */
    public static final class Result {
        /** Concatenated 9F5B values, 5 bytes per script (EMV v4.4 Book 4 Annex A5). */
        public final byte[] results;
        public final boolean anyFailed;
        public final boolean failedBeforeFinalAc;
        public final boolean failedAfterFinalAc;
        public final int commandsSent;

        Result(byte[] results, boolean anyFailed, boolean before, boolean after, int commandsSent) {
            this.results = results;
            this.anyFailed = anyFailed;
            this.failedBeforeFinalAc = before;
            this.failedAfterFinalAc = after;
            this.commandsSent = commandsSent;
        }
    }

    private IssuerScriptProcessor() {
    }

    /**
     * Processes the given templates in order, sending every 86 command.  A
     * non-9000 response stops the current script and is reported as a failure;
     * the remaining templates are still processed (the terminal sends each
     * script independently).
     *
     * @param afterFinalAc whether the scripts were received after the final
     *                     GENERATE AC (selects the TVR failure bit)
     */
    public static Result process(Terminal terminal, boolean afterFinalAc, byte[]... templates)
            throws Exception {
        ByteArrayOutputStream results = new ByteArrayOutputStream();
        boolean anyFailed = false;
        boolean before = false;
        boolean after = false;
        int sent = 0;
        // The total length of all Issuer Scripts in one response is limited to
        // 128 bytes; a single 86 command without a Script Identifier to 124
        // (EMV v4.4 Book 4 §6.3.9).  The cumulative total spans all templates.
        int cumulative = 0;
        for (byte[] template : templates) {
            SmCrypto.IssuerScript script;
            try {
                script = SmCrypto.parseIssuerScript(template);
            } catch (RuntimeException e) {
                // Annex E Scenario 3 / Book 4 §12.2.4: a script that does not
                // parse is reported as 'Script not performed' (9F5B byte 1
                // result 0), sets the script-processing TVR bits, and the
                // remaining scripts are still processed.
                results.write(SmCrypto.issuerScriptResults(0, 0, null));
                anyFailed = true;
                if (afterFinalAc) {
                    after = true;
                } else {
                    before = true;
                }
                continue;
            }
            int scriptLength = 0;
            boolean tooLong = false;
            for (byte[] command : script.commands) {
                scriptLength += command.length;
                if (command.length > 124) {
                    tooLong = true;
                }
            }
            cumulative += scriptLength;
            if (tooLong || cumulative > 128) {
                // Script length error: reported as 'Script not performed' and
                // the TVR script bits are set (EMV v4.4 Book 4 §6.3.9/§12.2.4).
                results.write(SmCrypto.issuerScriptResults(0, 0, script.scriptId));
                anyFailed = true;
                if (afterFinalAc) {
                    after = true;
                } else {
                    before = true;
                }
                continue;
            }
            int sequence = 0;
            boolean failed = false;
            int failSequence = 0;
            for (byte[] command : script.commands) {
                sequence++;
                sent++;
                ResponseAPDU response = terminal.transmit(command);
                // EMV v4.4 Book 3 §10.10: examine only SW1; normal processing
                // ('90') or a 'warning' ('62'/'63') continues with the next
                // command, an 'error' terminates the script.
                int sw1 = response.getSW1();
                if (sw1 != 0x90 && sw1 != 0x62 && sw1 != 0x63) {
                    failed = true;
                    failSequence = sequence;
                    break;
                }
            }
            int nibble = failed ? (failSequence >= 15 ? 0x0F : failSequence) : 0;
            results.write(SmCrypto.issuerScriptResults(failed ? 1 : 2, nibble, script.scriptId));
            if (failed) {
                anyFailed = true;
                if (afterFinalAc) {
                    after = true;
                } else {
                    before = true;
                }
            }
        }
        return new Result(results.toByteArray(), anyFailed, before, after, sent);
    }

    /** Applies a result to the TVR byte 5 script-processing bits. */
    public static void applyToTvr(Result result, byte[] tvr) {
        if (result.failedBeforeFinalAc) {
            SmCrypto.setScriptFailure(tvr, false);
        }
        if (result.failedAfterFinalAc) {
            SmCrypto.setScriptFailure(tvr, true);
        }
    }
}
