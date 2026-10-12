package card42.test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.CardSecurity;
import card42.host.emrtd.lds.ChipAuthenticationInfo;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.ta.TaChain;
import card42.host.emrtd.ta.TerminalAuth;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Shared Chip + Terminal Authentication helper for the eMRTD integration
 * suites (ICAO Doc 9303-11 §6.2/§7.1).  EF.CardAccess/EF.CardSecurity are read
 * from the master file (read access PACE), CA re-keys the secure messaging and
 * TA authenticates the terminal with the demo chain the personalization wrote
 * into the FF07 trust point ({@link TaChain#demo}).
 */
final class TaSupport {

    private TaSupport() {
    }

    /** Runs Chip Authentication and returns its result (terminal ephemeral key). */
    static ChipAuth.Result chipAuthentication(EmrtdTerminal terminal) throws Exception {
        CardAccess cardAccess = CardAccess.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS));
        ChipAuthenticationInfo caInfo = cardAccess.chipAuthenticationInfos().get(0);
        CardSecurity cardSecurity = CardSecurity.parse(
                LdsReader.read(terminal, LdsFileUtil.FID_CARD_SECURITY));
        byte[] chipPublicKeyW = cardSecurity.publicKeyInfos().get(0).rawPoint();
        return ChipAuth.authenticateResult(terminal, chipPublicKeyW, caInfo);
    }

    /** Runs Terminal Authentication with the demo chain. */
    static void terminalAuthentication(EmrtdTerminal terminal, Pace.Session pace,
                                       byte[] caKeyHash, SecureRandom random) throws Exception {
        TaChain.Chain chain = TaChain.demo(random);
        List<CvCertificate> parsed = new ArrayList<CvCertificate>();
        for (byte[] encoded : chain.toSend()) {
            parsed.add(CvCertificateCodec.parse(encoded));
        }
        TerminalAuth.authenticate(terminal, parsed, chain.terminalPrivateScalar,
                TerminalAuth.chipIdentifier(pace.piccPublicKey), caKeyHash, random);
    }

    /** Runs Chip + Terminal Authentication. */
    static void authenticate(EmrtdTerminal terminal, Pace.Session pace, SecureRandom random)
            throws Exception {
        ChipAuth.Result ca = chipAuthentication(terminal);
        terminalAuthentication(terminal, pace,
                TerminalAuth.chipAuthenticationKeyHash(ca.terminalPublicKeyW), random);
    }
}
