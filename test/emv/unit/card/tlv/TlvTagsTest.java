package card42.test;

import card42.emv.TlvTags;

/**
 * EMV tag constants used by the shared TLV codec tests.
 *
 * <p>The TLV reader/writer coverage lives in
 * {@code test/common/unit/card/tlv/TlvTest.java}; this suite only locks the
 * EMV tag values that the codec callers depend on.
 */
final class TlvTagsTest {

    private TlvTagsTest() {
    }

    static void run() {
        System.out.println("TlvTags");
        Asserts.eq(0x5A, TlvTags.TAG_PAN, "TAG_PAN");
        Asserts.eq(0x5F24, TlvTags.TAG_EXPIRY_DATE, "TAG_EXPIRY_DATE");
    }
}
