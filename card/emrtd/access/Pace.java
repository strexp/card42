package card42.emrtd;

import card42.common.AesCmac;
import card42.common.ConstantTime;
import card42.common.RetailMac;
import card42.common.Tlv;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;

/* PACE, ECDH generic mapping, 3DES or AES-128 secure messaging
 * (BSI TR-03110-3 A.3/B.1, ICAO Doc 9303-11 §4.4).  The card holds the
 * PACE key seed (SHA-1(MRZ_info), DGI FF04) and derives K_pi from it; the
 * generic mapping uses the platform KeyAgreement ALG_EC_PACE_GM (verified on
 * the J3R180).
 *
 * GENERAL AUTHENTICATE steps:
 *   1. -> 7C{80: E(K_pi, s)}      (card nonce s; 8 bytes 3DES / 16 bytes AES)
 *   2. 7C{81: PK_PCD} -> 7C{82: PK_ICC}
 *   3. 7C{83: PK_PCD~} -> 7C{84: PK_ICC~}
 *   4. SM 7C{85: T_PCD} -> 7C{86: T_PICC}
 *
 * After step 3 the derived K_enc/K_mac replace the session keys and the SSC
 * restarts at zero; step 4 runs under the new secure messaging.  The negotiated
 * OID selects the SM cipher (3DES retail MAC or AES-CMAC) and the applet's SM
 * implementation.
 *
 * @author card42
 */

public final class Pace implements PaceSeedSink {

    /** OID prefix id-PACE-ECDH-GM-* (the last byte selects the cipher). */
    private static final byte[] OID_PREFIX = {
        0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02 };

    private static final byte STAGE_IDLE = 0;
    private static final byte STAGE_AT = 1;
    private static final byte STAGE_NONCE = 2;
    private static final byte STAGE_MAPPED = 3;
    private static final byte STAGE_KEYED = 4;

    private final byte[] seed = new byte[20];
    private boolean seedSet;
    private byte stage;
    private boolean aes;
    private final byte[] oid = new byte[10];

    private final byte[] kpi = new byte[16];
    private final byte[] nonce = new byte[16];
    private final byte[] nonceScalar = new byte[32];

    private final byte[] peer = new byte[65];      // PK_PCD~ (for T_PICC)
    private final byte[] ephPicc = new byte[65];   // PK_ICC~ (for T_PCD)
    private final byte[] mapped = new byte[65];    // G'
    private final byte[] scratch = new byte[96];
    private final byte[] tokenInput = new byte[96];
    private final byte[] tokenMac = new byte[16];

    /*
     * The PACE EC keys are built once and reused across sessions.  Allocating a
     * fresh KeyPair / ECPrivateKey on every PACE would exhaust the persistent
     * heap of a card whose JCRE does not reclaim promptly (J3R180): repeated
     * PACE then returns 6F00 (observed after ~9 sessions).  Reusing the objects
     * keeps the persistent footprint constant.
     */
    private ECPrivateKey nonceKey;
    private KeyPair mappingPair;
    private KeyPair ephemeralPair;

    /** Reusable TLV search result (offset, length); avoids per-command arrays. */
    private final short[] findResult = new short[2];

    private final KeyAgreement gm;
    private final KeyAgreement xy;
    private final KeyAgreement plain;

    private final Sha1Kdf kdf;
    private final RetailMac mac;
    private final AesCmac aesMac;
    private final Cipher des3;
    private final DESKey desKey;
    private final Cipher aesCbc;
    private final AESKey aesKey;
    private final byte[] zeroIv8 = new byte[8];
    private final byte[] zeroIv16 = new byte[16];

    public Pace() {
        kdf = new Sha1Kdf();
        mac = new RetailMac();
        aesMac = new AesCmac();
        des3 = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_2KEY, false);
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128, false);
        gm = KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
        xy = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        plain = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        stage = STAGE_IDLE;
    }

    /** Stores the 20-byte PACE key seed SHA-1(MRZ_info) (perso DGI FF04). */
    public void setSeed(byte[] src, short off, short len) {
        if (len != (short) 20) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(src, off, seed, (short) 0, (short) 20);
        seedSet = true;
    }

    public boolean seedSet() {
        return seedSet;
    }

    /** True when the negotiated profile is AES (else 3DES). */
    public boolean isAes() {
        return aes;
    }

    public void reset() {
        stage = STAGE_IDLE;
    }

    /** MSE:Set AT: data = DO'80'(PACE OID) || DO'83'(password reference) || DO'84'. */
    public void mseSetAt(byte[] data, short off, short len) {
        if (!seedSet) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short[] r = findResult;
        if (!Lds2Record.find(data, off, len, EmrtdTags.DO_PACE_NONCE, r)
                || r[1] != (short) 10
                || !equal(data, r[0], OID_PREFIX, (short) 9)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte variant = data[(short) (r[0] + 9)];
        if (variant == (byte) 0x01) {
            aes = false;
        } else if (variant == (byte) 0x02) {
            aes = true;
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA); // only 3DES / AES-128
        }
        Util.arrayCopyNonAtomic(data, r[0], oid, (short) 0, (short) 10);
        if (Lds2Record.find(data, off, len, EmrtdTags.DO_PACE_PASSWORD_REF, r)
                && (r[1] < (short) 1 || data[r[0]] != (byte) 0x01)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA); // only MRZ (0x01)
        }
        derive(kpi, (short) 0, seed, (short) 0, (short) 20, (byte) 3);
        stage = STAGE_AT;
    }

    private static boolean equal(byte[] a, short aOff, byte[] b, short len) {
        return Util.arrayCompare(a, aOff, b, (short) 0, len) == 0;
    }

    /** GENERAL AUTHENTICATE; writes the 7C-wrapped response to out. */
    public short generalAuthenticate(EmrtdApplet applet, byte[] data, short off, short len,
                                     byte[] out) {
        switch (stage) {
        case STAGE_AT:
            return step1(applet, out);
        case STAGE_NONCE:
            return step2(data, off, len, out);
        case STAGE_MAPPED:
            return step3(applet, data, off, len, out);
        case STAGE_KEYED:
            return step4(applet, data, off, len, out);
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return 0;
        }
    }

    /** Step 1: nonce s and E(K_pi, s). */
    private short step1(EmrtdApplet applet, byte[] out) {
        short nonceLen = aes ? (short) 16 : (short) 8;
        applet.random.generateData(nonce, (short) 0, nonceLen);
        Util.arrayFillNonAtomic(nonceScalar, (short) 0, (short) 32, (byte) 0);
        Util.arrayCopyNonAtomic(nonce, (short) 0, nonceScalar,
                (short) (32 - nonceLen), nonceLen);
        if (nonceKey == null) {
            nonceKey = (ECPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            P256.setCurve(nonceKey);
        }
        nonceKey.setS(nonceScalar, (short) 0, (short) 32);
        encrypt(kpi, nonce, (short) 0, nonceLen, scratch, (short) 0);
        stage = STAGE_NONCE;
        return wrap(EmrtdTags.DO_PACE_NONCE, scratch, (short) 0, nonceLen, out);
    }

    /** Step 2: mapping keys; G' = [s]G + H. */
    private short step2(byte[] data, short off, short len, byte[] out) {
        short[] r = findResult;
        if (!Lds2Record.find(data, off, len, EmrtdTags.DO_PACE_MAP_PCD, r)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (mappingPair == null) {
            mappingPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            P256.setCurve((ECPublicKey) mappingPair.getPublic());
            P256.setCurve((ECPrivateKey) mappingPair.getPrivate());
        }
        mappingPair.genKeyPair();

        // H = ECDH(SK_ICC, PK_PCD) as an uncompressed point.
        xy.init(mappingPair.getPrivate());
        short hl = xy.generateSecret(data, r[0], r[1], scratch, (short) 0);
        short hOff = 0;
        short hLen = hl;
        if (hl == (short) 64) {
            peer[0] = (byte) 0x04;
            Util.arrayCopyNonAtomic(scratch, (short) 0, peer, (short) 1, (short) 64);
            hLen = 65;
        } else {
            Util.arrayCopyNonAtomic(scratch, (short) 0, peer, (short) 0, hl);
        }
        // G' = [s]G + H.
        gm.init(nonceKey);
        short ml = gm.generateSecret(peer, hOff, hLen, mapped, (short) 0);

        if (ephemeralPair == null) {
            ephemeralPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            P256.setCurve((ECPublicKey) ephemeralPair.getPublic());
            P256.setCurve((ECPrivateKey) ephemeralPair.getPrivate());
        }
        ((ECPublicKey) ephemeralPair.getPublic()).setG(mapped, (short) 0, ml);
        ((ECPrivateKey) ephemeralPair.getPrivate()).setG(mapped, (short) 0, ml);
        ephemeralPair.genKeyPair();

        short pl = ((ECPublicKey) mappingPair.getPublic()).getW(scratch, (short) 0);
        stage = STAGE_MAPPED;
        return wrap(EmrtdTags.DO_PACE_MAP_PICC, scratch, (short) 0, pl, out);
    }

    /** Step 3: ephemeral keys on G'; derive the session keys. */
    private short step3(EmrtdApplet applet, byte[] data, short off, short len, byte[] out) {
        short[] r = findResult;
        if (!Lds2Record.find(data, off, len, EmrtdTags.DO_PACE_EPH_PCD, r)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(data, r[0], peer, (short) 0, r[1]);

        plain.init(ephemeralPair.getPrivate());
        short kl = plain.generateSecret(data, r[0], r[1], scratch, (short) 0);
        derive(applet.ksEnc, (short) 0, scratch, (short) 0, kl, (byte) 1);
        derive(applet.ksMac, (short) 0, scratch, (short) 0, kl, (byte) 2);
        Util.arrayFillNonAtomic(applet.ssc, (short) 0, (short) 8, (byte) 0);
        // Secure messaging is not "established" until the terminal proves it
        // knows K_mac in step 4 (the fresh-PACE step 4 is sent in the clear, as
        // in jMRTD); only then does a plaintext APDU abort the session.
        short pl = ((ECPublicKey) ephemeralPair.getPublic()).getW(ephPicc, (short) 0);
        stage = STAGE_KEYED;
        return wrap(EmrtdTags.DO_PACE_EPH_PICC, ephPicc, (short) 0, pl, out);
    }

    /** Step 4: verify T_PCD and answer T_PICC (under the new SM). */
    private short step4(EmrtdApplet applet, byte[] data, short off, short len, byte[] out) {
        short[] r = findResult;
        if (!Lds2Record.find(data, off, len, EmrtdTags.DO_PACE_TOKEN_PCD, r)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short n = tokenInput(ephPicc);
        tokenMac(applet.ksMac, n);
        if (r[1] != (short) 8
                || !ConstantTime.equals(tokenMac, (short) 0, data, r[0], (short) 8)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        n = tokenInput(peer);
        tokenMac(applet.ksMac, n);
        stage = STAGE_IDLE;
        // PACE succeeded: secure messaging is now established and the LDS2 /
        // EF.CardSecurity access condition is satisfied for this session.
        applet.smEstablished = true;
        applet.paceDone = true;
        return wrap(EmrtdTags.DO_PACE_TOKEN_PICC, tokenMac, (short) 0, (short) 8, out);
    }

    private void tokenMac(byte[] ksMac, short len) {
        if (aes) {
            aesMac.mac(ksMac, (short) 0, (short) 16, tokenInput, (short) 0, len,
                    tokenMac, (short) 0);
        } else {
            mac.mac(ksMac, (short) 0, (short) 16, tokenInput, (short) 0, len,
                    tokenMac, (short) 0);
        }
    }

    /** 7F49 { 06 <OID> 86 <uncompressed point> } for the auth token MAC. */
    private short tokenInput(byte[] point) {
        short p = 0;
        p = Tlv.append((short) 0x06, oid, (short) 0, (short) 10, tokenInput, p);
        p = Tlv.append((short) 0x86, point, (short) 0, (short) 65, tokenInput, p);
        short header = (short) (2 + Tlv.lengthSize(p)); // 7F49 + BER length
        for (short i = (short) (p - 1); i >= 0; i--) {
            tokenInput[(short) (i + header)] = tokenInput[i];
        }
        tokenInput[0] = (byte) 0x7F;
        tokenInput[1] = (byte) 0x49;
        Tlv.appendLength(p, tokenInput, (short) 2);
        return (short) (header + p);
    }

    /** KDF(x, counter) = SHA-1(x || 00 00 00 counter), 16-byte key. */
    private void derive(byte[] out, short outOff, byte[] x, short xOff, short xLen,
                        byte counter) {
        // DES parity adjustment applies to 3DES keys only (BSI A.2.3.1).
        kdf.derive(x, xOff, xLen, counter, out, outOff, !aes);
    }

    /** Encrypts whole blocks with a zero IV (3DES-CBC or AES-CBC). */
    private void encrypt(byte[] key, byte[] in, short inOff, short inLen,
                         byte[] out, short outOff) {
        if (aes) {
            aesKey.setKey(key, (short) 0);
            aesCbc.init(aesKey, Cipher.MODE_ENCRYPT, zeroIv16, (short) 0, (short) 16);
            aesCbc.doFinal(in, inOff, inLen, out, outOff);
        } else {
            desKey.setKey(key, (short) 0);
            des3.init(desKey, Cipher.MODE_ENCRYPT, zeroIv8, (short) 0, (short) 8);
            des3.doFinal(in, inOff, inLen, out, outOff);
        }
    }

    /** Writes 7C { tag value } to out and returns its length. */
    private static short wrap(short tag, byte[] value, short vOff, short vLen, byte[] out) {
        short p = (short) 2;
        p = Tlv.append(tag, value, vOff, vLen, out, p);
        out[0] = (byte) 0x7C;
        out[1] = (byte) (p - 2);
        return p;
    }
}
