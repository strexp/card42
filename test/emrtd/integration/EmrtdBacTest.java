package card42.test;

import java.security.SecureRandom;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.transport.Terminal;
import card42.host.common.util.Args;
import card42.host.emrtd.access.Bac;
import card42.host.emrtd.access.MrzKeySeed;
import card42.host.emrtd.aa.ActiveAuthentication;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.Com;
import card42.host.emrtd.lds.Dg1;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.lds.Dg2;
import card42.host.emrtd.lds.LdsFileUtil;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.lds.LdsSecurityObject;
import card42.host.emrtd.lds.Sod;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.PassiveAuthentication;
import card42.host.emrtd.perso.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end eMRTD LDS1 test: SELECT the LDS1 DF,
 * run BAC, then read DG1/DG15/COM through ISO 7816-4 secure messaging and
 * verify Active Authentication.  The passport is the ICAO Doc 9303-11 sample
 * personalized by {@code EmrtdPersoExporter}.
 */
public final class EmrtdBacTest {

    private EmrtdBacTest() {
    }

    public static void main(String[] argv) throws Exception {
        Args args = new Args(argv, new String[] { "host" }, new String[0]);
        String host = args.get("host", "socket:localhost:9025");
        CardTerminal cardTerminal = TestTerminals.getTerminal(host.split(":"));
        if (cardTerminal == null || !cardTerminal.waitForCardPresent(10000)) {
            throw new IllegalStateException("Connection to simulator failed on " + host);
        }
        Card card = cardTerminal.connect("*");
        try {
            run(new EmrtdTerminal(new Terminal(card.getBasicChannel())));
        } finally {
            card.disconnect(true);
        }
        if (Checks.failures() > 0) {
            System.out.println("FAILED: " + Checks.failures() + " eMRTD check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD BAC CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        ResponseAPDU selected = terminal.selectLds1();
        Checks.check("SELECT LDS1", selected.getSW(), 0x9000);

        // The applet implements javacardx.apdu.ExtendedLength, so an
        // extended-length INTERNAL AUTHENTICATE (as a conformant reader sends
        // for an RSA-2048 AA key) must reach it and return the 256-byte
        // signature.
        byte[] extChallenge = new byte[8];
        new SecureRandom().nextBytes(extChallenge);
        byte[] extApdu = new byte[17];
        extApdu[1] = (byte) 0x88;
        extApdu[6] = 0x08;
        System.arraycopy(extChallenge, 0, extApdu, 7, 8);
        ResponseAPDU extended = terminal.base().transmit(extApdu);
        Checks.check("extended-length INTERNAL AUTHENTICATE reaches the applet",
                extended.getSW(), 0x9000);
        Checks.check("extended AA signature length", extended.getData().length, 256);

        // Active Authentication is run in the clear: the 256-byte RSA signature
        // does not fit an SM-wrapped short APDU.  DG15 is a public key and is
        // readable without BAC.
        byte[] dg15 = LdsReader.read(terminal, LdsFileUtil.FID_DG15);
        Dg15 parsedDg15 = Dg15.parse(dg15);
        Checks.check("DG15 AA key present", parsedDg15.modulus.signum() > 0);

        // The short-EF-identifier READ BINARY form is MANDATORY for the eMRTD
        // (Doc 9303-10 §3.6.3.2 Table 5) and is what most inspection
        // systems use; it must return the same window as SELECT FILE + READ
        // BINARY, here in the clear.  A single READ BINARY is capped at one
        // block, so compare the returned window.
        ResponseAPDU dg15Sfi = terminal.readBinarySfi(0x0F, 0, LdsReader.CHUNK);
        Checks.check("SFI READ BINARY DG15", dg15Sfi.getSW(), 0x9000);
        Checks.check("SFI READ BINARY DG15 window", dg15Sfi.getData().length,
                LdsReader.CHUNK);
        Checks.bytes(java.util.Arrays.copyOf(dg15, dg15Sfi.getData().length),
                dg15Sfi.getData(), "SFI READ BINARY DG15 data");
        ResponseAPDU unknownSfi = terminal.readBinarySfi(0x1F, 0, 0x08);
        Checks.check("unknown SFI -> 6A82", unknownSfi.getSW(), 0x6A82);
        byte[] challenge = new byte[8];
        new SecureRandom().nextBytes(challenge);
        boolean aa = ActiveAuthentication.verify(terminal, parsedDg15, challenge);
        Checks.check("Active Authentication verifies", aa);

        byte[] seed = MrzKeySeed.seed(EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        Bac.Session session = Bac.authenticate(terminal, seed);
        Checks.check("BAC mutual authentication", true);
        terminal.setSecureMessaging(session.secureMessaging());

        byte[] dg1 = LdsReader.read(terminal, LdsFileUtil.FID_DG1);
        Dg1 parsed = Dg1.parse(dg1);
        Checks.check("DG1 document number", EmrtdPersoExporter.DOCUMENT_NUMBER
                .equals(parsed.documentNumber));
        Checks.check("DG1 surname", "ERIKSSON".equals(parsed.surname));
        Checks.check("DG1 date of birth", EmrtdPersoExporter.DATE_OF_BIRTH
                .equals(parsed.dateOfBirth));

        // DG2 is personalized with a real (synthetic) JPEG face.  It is larger
        // than the old 4096-byte personalization buffer, so this read exercises
        // the streaming personalization and the paged EF end to end.
        byte[] dg2Bytes = LdsReader.read(terminal, LdsFileUtil.FID_DG2);
        Checks.check("DG2 exceeds the old 4096-byte personalization buffer",
                dg2Bytes.length > 4096);
        Dg2 parsedDg2 = Dg2.parse(dg2Bytes);
        Checks.check("DG2 carries a JPEG face image", parsedDg2.image != null
                && (parsedDg2.image[0] & 0xFF) == 0xFF
                && (parsedDg2.image[1] & 0xFF) == 0xD8
                && parsedDg2.image.length > 1000);

        byte[] com = LdsReader.read(terminal, LdsFileUtil.FID_COM);
        Com parsedCom = Com.parse(com);
        Checks.check("COM LDS version", "0107".equals(parsedCom.ldsVersion));

        // EF.CardAccess at FID 011C advertises PACE (Doc 9303-10 §3.11.3).
        byte[] cardAccessBytes = LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS);
        CardAccess cardAccess = CardAccess.parse(cardAccessBytes);
        Checks.check("LDS1 EF.CardAccess has PACE infos", !cardAccess.paceInfos().isEmpty());
        Checks.check("LDS1 EF.CardAccess selects ECDH generic mapping",
                cardAccess.selectPace() != null && cardAccess.selectPace().isEcdhGenericMapping());

        // MF-level EF.CardAccess read: a reader may SELECT MF and then read
        // 011C before selecting the eMRTD application (the applet is Default
        // Selected on a real card).  The by-FID read must return the same file.
        ResponseAPDU mf = terminal.selectMf();
        Checks.check("SELECT MF", mf.getSW(), 0x9000);
        byte[] mfCardAccess = LdsReader.read(terminal, LdsFileUtil.FID_CARD_ACCESS);
        Checks.bytes(cardAccessBytes, mfCardAccess, "MF-level EF.CardAccess matches");

        // Short-EF-identifier READ BINARY through secure messaging: DG1 (SFI
        // 0x01) and EF.COM (SFI 0x1E) must match the SELECT FILE reads.
        ResponseAPDU dg1Sfi = terminal.readBinarySfi(0x01, 0, LdsReader.CHUNK);
        Checks.check("SFI READ BINARY DG1 (SM)", dg1Sfi.getSW(), 0x9000);
        Checks.bytes(dg1, dg1Sfi.getData(), "SFI READ BINARY DG1 data (SM)");
        ResponseAPDU comSfi = terminal.readBinarySfi(0x1E, 0, LdsReader.CHUNK);
        Checks.check("SFI READ BINARY COM (SM)", comSfi.getSW(), 0x9000);
        Checks.bytes(com, comSfi.getData(), "SFI READ BINARY COM data (SM)");

        byte[] sodBytes = LdsReader.read(terminal, LdsFileUtil.FID_SOD);
        CscaKeyStore trust = CscaKeyStore.fromFiles(new java.io.File("perso/emrtd/csca.crt"));
        LdsSecurityObject securityObject = PassiveAuthentication.verify(Sod.parse(sodBytes), trust);
        Checks.check("SOD DSC chain + signature verify", true);
        Checks.check("DG1 hash matches the SOD",
                PassiveAuthentication.verifyDataGroup(securityObject, 1, dg1));
        Checks.check("DG2 hash matches the SOD",
                PassiveAuthentication.verifyDataGroup(securityObject, 2, dg2Bytes));
        Checks.check("DG15 hash matches the SOD",
                PassiveAuthentication.verifyDataGroup(securityObject, 15, dg15));

        // ISO/IEC 7816-4 §6.1.2: a short-EF-identifier READ BINARY sets that EF
        // as the current EF.  A reader relies on this to finish an EF larger than
        // 256 bytes with offset READ BINARYs after its SFI prefix reads, so the
        // offset read must continue the SFI-addressed EF with no SELECT.
        LdsReader.read(terminal, LdsFileUtil.FID_COM); // current EF = COM
        terminal.readBinarySfi(0x1D, 0, 0x08);         // SFI read of SOD
        ResponseAPDU sodOffset = terminal.readBinary(0x100, 0x40);
        Checks.check("offset READ BINARY after SFI keeps the current EF",
                sodOffset.getSW(), 0x9000);
        Checks.bytes(java.util.Arrays.copyOfRange(sodBytes, 0x100,
                        0x100 + sodOffset.getData().length),
                sodOffset.getData(), "SOD offset read after SFI READ BINARY");
    }
}
