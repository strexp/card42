package card42.test;

import card42.host.emrtd.lds.security.*;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.common.CardAccess;
import card42.host.emrtd.lds.common.CardSecurity;
import card42.host.emrtd.lds.security.ChipAuthenticationInfo;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.tools.TaChain;
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

    /** Runs Chip Authentication with the first advertised CA profile. */
    static ChipAuth.Result chipAuthentication(EmrtdTerminal terminal) throws Exception {
        CardAccess cardAccess = CardAccess.parse(
                LdsReader.readMf(terminal, LdsFileUtil.FID_CARD_ACCESS));
        return chipAuthentication(terminal, cardAccess.chipAuthenticationInfos().get(0));
    }

    /** Runs Chip Authentication with an explicit CA profile (3DES or AES-128). */
    static ChipAuth.Result chipAuthentication(EmrtdTerminal terminal,
                                              ChipAuthenticationInfo caInfo) throws Exception {
        CardSecurity cardSecurity = CardSecurity.parse(
                LdsReader.readMf(terminal, LdsFileUtil.FID_CARD_SECURITY));
        byte[] chipPublicKeyW = cardSecurity.publicKeyInfos().get(0).rawPoint();
        return ChipAuth.authenticateResult(terminal, chipPublicKeyW, caInfo);
    }

    /** Runs Terminal Authentication with the demo chain. */
    static void terminalAuthentication(EmrtdTerminal terminal, Pace.Session pace,
                                       byte[] caKeyHash, SecureRandom random) throws Exception {
        terminalAuthentication(terminal, pace, caKeyHash, random, false);
    }

    /**
     * Runs Terminal Authentication with the demo ECDSA ({@code rsa == false}) or
     * RSA-PSS ({@code rsa == true}) chain.  Both CVCA trust points are
     * personalized, so either chain verifies.
     */
    static void terminalAuthentication(EmrtdTerminal terminal, Pace.Session pace,
                                       byte[] caKeyHash, SecureRandom random, boolean rsa)
            throws Exception {
        terminalAuthentication(terminal, pace, caKeyHash,
                rsa ? TaChain.demoRsa() : TaChain.demo(random), random);
    }

    /** Runs Terminal Authentication with an explicitly issued chain. */
    static void terminalAuthentication(EmrtdTerminal terminal, Pace.Session pace,
                                       byte[] caKeyHash, TaChain.Chain chain,
                                       SecureRandom random) throws Exception {
        List<CvCertificate> parsed = new ArrayList<CvCertificate>();
        for (byte[] encoded : chain.toSend()) {
            parsed.add(CvCertificateCodec.parse(encoded));
        }
        TerminalAuth.authenticate(terminal, parsed, chain.terminalPrivateScalar,
                chain.terminalRsaKey, TerminalAuth.chipIdentifier(pace.piccPublicKey),
                caKeyHash, random);
    }

    /** Runs Chip + Terminal Authentication with the demo chain. */
    static void authenticate(EmrtdTerminal terminal, Pace.Session pace, SecureRandom random)
            throws Exception {
        authenticate(terminal, pace, random, TaChain.demo(random));
    }

    /** Runs Chip + Terminal Authentication with an explicitly issued chain. */
    static void authenticate(EmrtdTerminal terminal, Pace.Session pace, SecureRandom random,
                             TaChain.Chain chain) throws Exception {
        ChipAuth.Result ca = chipAuthentication(terminal);
        terminalAuthentication(terminal, pace,
                TerminalAuth.chipAuthenticationKeyHash(ca.terminalPublicKeyW), chain, random);
    }
}
