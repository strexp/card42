package card42.test;
import card42.host.emv.kernel.analysis.TerminalActionAnalysis;
import card42.host.emv.kernel.data.Tvr;

/**
 * Unit tests for {@link TerminalActionAnalysis} (EMV v4.4 Book 3 §10.7).
 */
final class TerminalActionAnalysisTest {

    private TerminalActionAnalysisTest() {
    }

    static void run() {
        System.out.println("TerminalActionAnalysisTest");

        byte[] zero = Tvr.blank();
        byte[] denial = Tvr.blank();
        denial[0] = (byte) 0x80;
        byte[] online = Tvr.blank();
        online[3] = (byte) 0x80;
        byte[] def = Tvr.blank();
        def[4] = (byte) 0x40;

        // TAC-Denial triggers -> AAC.
        Asserts.eq(0x00, TerminalActionAnalysis.firstAcOnlineCapable(
                denial, denial, zero, null, null), "TAC-Denial -> AAC");
        // IAC-Denial (card sourced) triggers -> AAC.
        Asserts.eq(0x00, TerminalActionAnalysis.firstAcOnlineCapable(
                denial, zero, zero, denial, null), "IAC-Denial -> AAC");
        // TAC-Online triggers -> ARQC.
        Asserts.eq(0x80, TerminalActionAnalysis.firstAcOnlineCapable(
                online, zero, online, null, null) & 0xFF, "TAC-Online -> ARQC");
        // An absent IAC-Online defaults to all bits 1 (EMV v4.4 Book 3 §10.7): any TVR
        // bit forces the transaction online.
        Asserts.eq(0x80, TerminalActionAnalysis.firstAcOnlineCapable(
                online, zero, zero, null, null) & 0xFF, "absent IAC-Online -> ARQC");
        // Denial is processed before Online.
        Asserts.eq(0x00, TerminalActionAnalysis.firstAcOnlineCapable(
                denial, denial, online, null, null), "Denial before Online");

        // Unable to go online: the Default pair decides TC vs AAC.  An absent
        // IAC-Default also defaults to all bits 1, so a TVR bit rejects.
        Asserts.eq(0x00, TerminalActionAnalysis.unableToGoOnline(def, def, null),
                "unable to go online + Default -> AAC");
        Asserts.eq(0x00, TerminalActionAnalysis.unableToGoOnline(online, zero, null),
                "absent IAC-Default + TVR bit -> AAC");
        Asserts.eq(0x40, TerminalActionAnalysis.unableToGoOnline(zero, zero, null),
                "clean TVR, absent IAC-Default -> TC");
        // A clean TVR never triggers the all-one default -> TC.
        Asserts.eq(0x40, TerminalActionAnalysis.firstAcOnlineCapable(
                zero, zero, zero, null, null), "clean TVR -> TC");

        // Offline-only terminal (EMV v4.4 Book 3 §10.7 option 2): the Denial
        // pair is processed, then the Default pair; the Online pair is skipped.
        Asserts.eq(0x00, TerminalActionAnalysis.firstAcOfflineOnly(
                denial, denial, null, zero, null), "offline-only TAC-Denial -> AAC");
        Asserts.eq(0x00, TerminalActionAnalysis.firstAcOfflineOnly(
                def, zero, null, def, zero), "offline-only TAC-Default -> AAC");
        Asserts.eq(0x40, TerminalActionAnalysis.firstAcOfflineOnly(
                online, zero, null, zero, zero),
                "offline-only skips the Online pair -> TC");
        Asserts.eq(0x40, TerminalActionAnalysis.firstAcOfflineOnly(
                zero, zero, null, zero, zero), "offline-only clean TVR -> TC");
    }
}
