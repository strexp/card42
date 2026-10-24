package card42.test;

import java.security.SecureRandom;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;

import card42.host.common.cli.Args;
import card42.host.common.transport.Terminal;
import card42.host.emrtd.access.LdsReader;
import card42.host.emrtd.access.Pace;
import card42.host.emrtd.lds.common.LdsDataGroup;
import card42.host.emrtd.lds.common.LdsFileUtil;
import card42.host.emrtd.lds.common.LdsParseResult;
import card42.host.emrtd.lds.common.ParseStatus;
import card42.host.emrtd.lds.lds1.Dg1;
import card42.host.emrtd.lds.lds1.Dg10;
import card42.host.emrtd.lds.lds1.Dg11;
import card42.host.emrtd.lds.lds1.Dg12;
import card42.host.emrtd.lds.lds1.Dg13;
import card42.host.emrtd.lds.lds1.Dg16;
import card42.host.emrtd.lds.lds1.Dg2;
import card42.host.emrtd.lds.lds1.Dg3;
import card42.host.emrtd.lds.lds1.Dg4;
import card42.host.emrtd.lds.lds1.Dg5;
import card42.host.emrtd.lds.lds1.Dg7;
import card42.host.emrtd.lds.lds1.Dg8;
import card42.host.emrtd.lds.lds1.Dg9;
import card42.host.emrtd.tools.EmrtdPersoExporter;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * End-to-end check that every data group the sample document carries is read
 * through secure messaging and turned into the LDS field model.
 *
 * <p>The LDS1 sample has a TA trust point, so DG3/DG4 require Terminal
 * Authentication with the ePassport CHAT bits; the suite performs
 * PACE -> Chip Authentication -> Terminal Authentication first, then reads
 * DG1-DG16 (DG6 is reserved and DG14/DG15 are security objects parsed
 * elsewhere).
 */
public final class EmrtdLdsParsersIntegrationTest {

    private EmrtdLdsParsersIntegrationTest() {
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
            System.out.println("FAILED: " + Checks.failures() + " LDS parser check(s)");
            System.exit(1);
        }
        System.out.println("ALL EMRTD LDS PARSER CHECKS PASSED");
    }

    static void run(EmrtdTerminal terminal) throws Exception {
        Checks.check("SELECT LDS1", terminal.selectLds1().getSW(), 0x9000);

        Pace.Session pace = Pace.authenticate(terminal, EmrtdPersoExporter.DOCUMENT_NUMBER,
                EmrtdPersoExporter.DATE_OF_BIRTH, EmrtdPersoExporter.DATE_OF_EXPIRY);
        terminal.setSecureMessaging(pace.secureMessaging());
        TaSupport.authenticate(terminal, pace, new SecureRandom());
        Checks.check("PACE + Chip + Terminal Authentication", true);

        byte[] dg1Bytes = LdsReader.read(terminal, LdsFileUtil.dgFid(1));
        Dg1 dg1 = Dg1.parse(dg1Bytes);
        Checks.check("DG1 MRZ is valid", dg1.status() == ParseStatus.OK);
        Checks.check("DG1 document number",
                EmrtdPersoExporter.DOCUMENT_NUMBER.equals(dg1.documentNumber));

        byte[] dg2Bytes = LdsReader.read(terminal, LdsFileUtil.dgFid(2));
        Dg2 dg2 = Dg2.parse(dg2Bytes);
        Checks.check("DG2 face image present",
                dg2.status() != ParseStatus.INVALID && dg2.image != null);
        Checks.check("DG2 CBEFF parsed", dg2.faces.size() == 1
                && dg2.faces.get(0).cbeff != null);

        byte[] dg3Bytes = LdsReader.read(terminal, LdsFileUtil.dgFid(3));
        Dg3 dg3 = Dg3.parse(dg3Bytes);
        Checks.check("DG3 finger parsed", dg3.status() != ParseStatus.INVALID
                && !dg3.fingers.isEmpty());
        Checks.check("DG3 finger image", dg3.fingers.get(0).image != null
                && dg3.fingers.get(0).position == 1);

        byte[] dg4Bytes = LdsReader.read(terminal, LdsFileUtil.dgFid(4));
        Dg4 dg4 = Dg4.parse(dg4Bytes);
        Checks.check("DG4 iris parsed", dg4.status() != ParseStatus.INVALID
                && !dg4.irises.isEmpty());
        Checks.check("DG4 right eye", dg4.irises.get(0).eyePosition == 1);

        byte[] dg5Bytes = LdsReader.read(terminal, LdsFileUtil.dgFid(5));
        Dg5 dg5 = Dg5.parse(dg5Bytes);
        Checks.check("DG5 portrait parsed", !dg5.portraits.isEmpty());

        byte[] dg7Bytes = LdsReader.read(terminal, LdsFileUtil.dgFid(7));
        Dg7 dg7 = Dg7.parse(dg7Bytes);
        Checks.check("DG7 signature parsed", !dg7.signatures.isEmpty());

        Dg8 dg8 = Dg8.parse(LdsReader.read(terminal, LdsFileUtil.dgFid(8)));
        Checks.check("DG8 templates parsed", dg8.status() == ParseStatus.OK
                && !dg8.templates.isEmpty());
        Dg9 dg9 = Dg9.parse(LdsReader.read(terminal, LdsFileUtil.dgFid(9)));
        Checks.check("DG9 templates parsed", !dg9.templates.isEmpty());
        Dg10 dg10 = Dg10.parse(LdsReader.read(terminal, LdsFileUtil.dgFid(10)));
        Checks.check("DG10 templates parsed", !dg10.templates.isEmpty());

        Dg11 dg11 = Dg11.parse(LdsReader.read(terminal, LdsFileUtil.dgFid(11)));
        Checks.check("DG11 fields parsed", dg11.status() != ParseStatus.INVALID
                && "ERIKSSON<<ANNA<MARIA".equals(dg11.fullName));
        Dg12 dg12 = Dg12.parse(LdsReader.read(terminal, LdsFileUtil.dgFid(12)));
        Checks.check("DG12 fields parsed", dg12.status() != ParseStatus.INVALID
                && "card42".equals(dg12.personalizationSystemSerial));
        Dg13 dg13 = Dg13.parse(LdsReader.read(terminal, LdsFileUtil.dgFid(13)));
        Checks.check("DG13 raw fields parsed", dg13.status() == ParseStatus.OK
                && dg13.value.length > 0);
        Dg16 dg16 = Dg16.parse(LdsReader.read(terminal, LdsFileUtil.dgFid(16)));
        Checks.check("DG16 persons parsed", dg16.status() != ParseStatus.INVALID
                && dg16.persons.size() == 2);
        Checks.check("DG16 first contact",
                "UTOPIA<CONTACT".equals(dg16.persons.get(0).name));

        // The generic dispatcher must agree with the dedicated parsers.
        int[] groups = { 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 16 };
        for (int group : groups) {
            byte[] raw = LdsReader.read(terminal, LdsFileUtil.dgFid(group));
            LdsParseResult<LdsDataGroup> result = LdsDataGroup.parse(group, raw);
            Checks.check("DG" + group + " dispatcher status", result.status == ParseStatus.OK
                    || result.status == ParseStatus.PARTIAL);
        }
    }
}
