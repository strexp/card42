package card42.test;

import java.math.BigInteger;

import card42.host.emv.oda.CaKey;
import card42.host.emv.oda.CaKeyStore;
import card42.host.emv.oda.SdaKeys;

/**
 * Test fixtures for the demo RSA key material used by the sample personalization
 * scripts ({@code perso/emv/sample.perso} / {@code perso/emv/sample-test.perso},
 * {@code @sda}) and by the ODA suites.
 *
 * <p>Two RSA-1024 key pairs with e = 65537: a demo Certification Authority that
 * signs the Issuer Public Key Certificate, and a demo Issuer that signs the SSAD
 * and the ICC public key certificates.  These keys are printed in the source on
 * purpose and <strong>must never be used on a real card</strong>; a real
 * deployment supplies its own {@link SdaKeys} profile and CA public key.
 *
 * <p>The same material is mirrored by {@code perso/emv/sample.perso.sda.keys} for
 * the CLI ({@code perso export -keys=<path>}); {@code PersoScriptTest} asserts
 * the two agree.
 */
final class TestKeys {

    private TestKeys() {
    }

    /** Demo CA private/public key pair (RSA-1024, e = 65537). */
    private static final String CA_N_HEX =
            "8328CDF41E543395FDB5D74A4F559CFBCA1CE46DCCDA74787D08377A591156"
            + "E0FA8D6100190864991279E5C3FFA8353AC13384DB7EFA5FA5BEBE91E95D"
            + "8C3C523FD26D5F4002C43E0871C62FB9C0265BBF2C5B5B7634F93F9C9E2B"
            + "E9ABACE7E4713983B4ADE1B3D731A2F6A0275FE94B9504512B5AC09D0AD1"
            + "2AE03171F8FF19";
    private static final String CA_D_HEX =
            "0D8AF61121DC91E307EA71CB737BA494FF1E929B9FCE62BE5A32B1FFC91898"
            + "3EECC01266FF2EB5AC7492EF9D98555701B5174BBD9A53E1F26C4AA3285487"
            + "7966E2CAEE7DA7DE9CE53A7B78582069110D98C7189D97D9D5D706295A2610"
            + "5349423068B64BA826E8AACF13F89A66AB8B5CA728F5CBF33CEE5F2B522D8C"
            + "D65BF19D";

    /** Demo Issuer private/public key pair (RSA-1024, e = 65537). */
    private static final String IS_N_HEX =
            "AA589BF9563BD87D7DF7FF53B7E1BA1A690BFC6069D5AC0EBC720924B83A1F"
            + "987799A457F38952607A2B5DCD0F5DEA2AB414764CBEC1444CEBF3E13695F1"
            + "6A568A458313246811F7CF7C2DC42F0BE78E197B59858565E27A8060F89B10"
            + "7D7DE7E9F07C5C2150C4094B16A0232DFBD710DB718D5175DB889494D6C4A4"
            + "690CF3F9";
    private static final String IS_D_HEX =
            "123FCDEDE7541FFC49BB80CA0A400F7CF6D606E29953FFCBD05A732A50E641"
            + "2E4759D96666BBC66C798A1DD1731CFF92359A9F95D735C3486E5AC13CE4D1"
            + "692FD0EEDAE41CF2EB6E4BDA84ACF76BA00182B4879791413961557F9429EF"
            + "796D779A27C5B888CFFA92ADF2F3B4663BEEBBB12E71CAC05B4BF3A26A8DE4"
            + "804AC965";

    /** Modulus length of both demo CA/Issuer keys, in bytes (RSA-1024). */
    static final int NCA = 128;
    static final int NI = 128;

    /** Length of the ICC DDA/CDA public key modulus (RSA-1024). */
    static final int NIC = 128;

    /** Length of the ICC PIN encipherment key and its modulus (RSA-1024). */
    static final int NPE = 128;

    /**
     * Length of the "leftmost digits" field of an ICC certificate: NI - 42
     * (EMV v4.4 Book 2, table 14/23).  The remaining NPE - (NI - 42) modulus bytes
     * are carried in the remainder tag (9F2F for the PIN key).
     */
    static final int PIN_LEFTOPMOST = NI - 42;

    /** Issuer public key exponent 01 00 01, as returned in tag 9F32. */
    static final byte[] EXPONENT = { 0x01, 0x00, 0x01 };

    static final BigInteger CA_MODULUS = new BigInteger(CA_N_HEX, 16);
    static final BigInteger CA_EXPONENT = BigInteger.valueOf(65537);
    static final BigInteger ISSUER_MODULUS = new BigInteger(IS_N_HEX, 16);

    /** Private exponents, used by the SDA generator only. */
    static final BigInteger CA_PRIVATE_EXPONENT = new BigInteger(CA_D_HEX, 16);
    static final BigInteger ISSUER_PRIVATE_EXPONENT = new BigInteger(IS_D_HEX, 16);

    /** CA Public Key Index advertised in tag 8F. */
    static final byte[] CA_PUBLIC_KEY_INDEX = { 0x01 };

    /** The SDA generator profile for the demo keys. */
    static SdaKeys sdaKeys() {
        return new SdaKeys(CA_MODULUS, CA_PRIVATE_EXPONENT,
                ISSUER_MODULUS, ISSUER_PRIVATE_EXPONENT,
                CA_PUBLIC_KEY_INDEX.clone(), EXPONENT.clone());
    }

    /** A CA key store that trusts the demo CA key at CA Public Key Index 8F=01. */
    static CaKeyStore caKeyStore() {
        return index -> (index != null && index.length == 1 && (index[0] & 0xFF) == 0x01)
                ? new CaKey(CA_MODULUS, CA_EXPONENT)
                : null;
    }
}
