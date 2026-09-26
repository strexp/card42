package card42.test;

import java.util.Arrays;

import javacard.framework.ISO7816;

import card42.emv.EMVRoles;
import card42.emv.EMVStaticData;
import card42.emv.PaymentData;
import card42.emv.RecordBuilder;
import card42.emv.RecordStore;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for {@link RecordBuilder}'s direct-send view
 * and the default record fallback: a stored '70' record
 * whose length field is already exact is served straight from the persistent
 * pool, while a placeholder length still goes through the response buffer
 * where it is normalised.
 *
 * <p>The response path maps to EMV v4.4 Book 3 §7; the direct-send/fallback
 * split is a project-internal optimisation.
 */
final class RecordBuilderTest {

    private RecordBuilderTest() {
    }

    static void run() {
        System.out.println("RecordBuilder");

        byte[] apdu = new byte[16];
        apdu[ISO7816.OFFSET_P1] = 0x01;
        apdu[ISO7816.OFFSET_P2] = 0x0C; // SFI 1

        // A stored record with an exact 70 length is served directly.
        EMVStaticData sd = new EMVStaticData();
        byte[] normalized = Hex.parse("70 03 5A 01 00");
        sd.setRecord((short) 0x0101, normalized, (short) 0, (short) normalized.length);
        RecordBuilder.View view = sd.directRecord(apdu);
        Asserts.check(view != null, "normalized stored record is served directly");
        Asserts.eq(normalized.length, view.length, "direct view length");
        Asserts.bytes(normalized,
                Arrays.copyOfRange(view.pool, view.offset, view.offset + view.length),
                "direct view content");

        // A long-form placeholder is not direct-servable; readRecord normalises it.
        byte[] placeholder = Hex.parse("70 82 00 03 5A 01 00");
        sd.setRecord((short) 0x0101, placeholder, (short) 0, (short) placeholder.length);
        Asserts.check(sd.directRecord(apdu) == null,
                "long-form placeholder length falls back to the response buffer");
        byte[] out = new byte[64];
        sd.readRecord(apdu, out, (byte) 0x00);
        Asserts.eq(0x70, out[0] & 0xFF, "normalised record keeps the 70 tag");
        Asserts.eq(0x03, out[1] & 0xFF, "normalised record 70 length");
        Asserts.eq(5, card42.common.Tlv.totalLength(out, (short) 0),
                "normalised record total length");

        // No stored record: the built-in default record 1 is used (not a view).
        EMVStaticData empty = new EMVStaticData();
        Asserts.check(empty.directRecord(apdu) == null,
                "no stored record -> no direct view");
        byte[] built = new byte[256];
        empty.readRecord(apdu, built, (byte) 0x00);
        Asserts.eq(0x70, built[0] & 0xFF, "default record 1 is a 70 template");

        // An unadvertised SFI is a missing file (6A82), also from the direct path.
        byte[] bad = new byte[16];
        bad[ISO7816.OFFSET_P1] = 0x01;
        bad[ISO7816.OFFSET_P2] = 0x14; // SFI 2
        Asserts.sw(ISO7816.SW_FILE_NOT_FOUND, () -> empty.directRecord(bad),
                "direct view rejects an unadvertised SFI");

        // Default records 2 and 3 are the SDA certificate placeholders
        // (EMV v4.4 Book 2 §5) when no certificate was personalized.
        byte[] apdu2 = new byte[16];
        apdu2[ISO7816.OFFSET_P1] = 0x02;
        apdu2[ISO7816.OFFSET_P2] = 0x0C; // SFI 1
        byte[] out2 = new byte[64];
        empty.readRecord(apdu2, out2, (byte) 0x00);
        Asserts.bytes(Hex.parse("70098F0090009200 9F3200"),
                Arrays.copyOf(out2, 11), "default record 2 placeholders");

        byte[] apdu3 = new byte[16];
        apdu3[ISO7816.OFFSET_P1] = 0x03;
        apdu3[ISO7816.OFFSET_P2] = 0x0C;
        byte[] out3 = new byte[64];
        empty.readRecord(apdu3, out3, (byte) 0x00);
        Asserts.bytes(Hex.parse("70029300"), Arrays.copyOf(out3, 4),
                "default record 3 placeholder");

        // Records 4 and 5 only exist once their certificates are personalized.
        byte[] apdu4 = new byte[16];
        apdu4[ISO7816.OFFSET_P1] = 0x04;
        apdu4[ISO7816.OFFSET_P2] = 0x0C;
        Asserts.sw(ISO7816.SW_RECORD_NOT_FOUND,
                () -> empty.readRecord(apdu4, new byte[64], (byte) 0x00),
                "default record 4 without a PIN certificate -> 6A83");
        byte[] apdu5 = new byte[16];
        apdu5[ISO7816.OFFSET_P1] = 0x05;
        apdu5[ISO7816.OFFSET_P2] = 0x0C;
        Asserts.sw(ISO7816.SW_RECORD_NOT_FOUND,
                () -> empty.readRecord(apdu5, new byte[64], (byte) 0x00),
                "default record 5 without an ICC certificate -> 6A83");

        // A stored record larger than the response buffer cannot be returned
        // in one piece and is reported as 6700 (docs/specs/emv/personalization.md §1).
        byte[] big = new byte[203];
        big[0] = 0x70;
        big[1] = (byte) 0x81;
        big[2] = (byte) 200;
        EMVStaticData bigStore = new EMVStaticData();
        bigStore.setRecord((short) 0x0101, big, (short) 0, (short) big.length);
        Asserts.sw(ISO7816.SW_WRONG_LENGTH,
                () -> bigStore.readRecord(apdu, new byte[64], (byte) 0x00),
                "oversized stored record -> 6700");

        // A malformed stored record (not a '70' template) is a missing record
        // (EMV v4.4 Book 3 §7.1 / §6.5.11); personalization would reject it, so
        // it is placed directly into the record store.
        RecordStore raw = new RecordStore();
        byte[] malformed = Hex.parse("5A0100");
        raw.put((short) 0x0101, malformed, (short) 0, (short) malformed.length);
        Asserts.sw(ISO7816.SW_RECORD_NOT_FOUND,
                () -> RecordBuilder.readRecord(raw, apdu, new byte[64],
                        EMVRoles.ROLE_CONTACT, new PaymentData()),
                "malformed stored record -> 6A83");
    }
}
