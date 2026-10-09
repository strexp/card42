package card42.emrtd;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/* LDS1 personalization: applies the DGI sequence to the file catalog, the BAC
 * seed and the AA key.
 *
 * The DGI number is the target FID; the project DGIs FF01/FF02 carry the BAC
 * K_seed and the AA private key.  Each DGI value is streamed in as it arrives
 * across the STORE DATA blocks ({@link DgiStream}); file values are appended
 * straight into the paged {@link LdsFile}, and only the small key DGIs are
 * buffered, so a large DG2 never occupies a whole-sequence buffer.  After the
 * last block the catalog builds EF.COM from the data-group index when no COM
 * was personalized.
 *
 * @author card42
 */

public final class LdsPerso extends DgiStream.Sink {

    /** DGI carrying the 16-byte BAC K_seed. */
    public static final short DGI_SEED = EmrtdTags.DGI_BAC_SEED;
    /** DGI carrying the AA private key (modLen || modulus || expLen || exponent). */
    public static final short DGI_AA_KEY = EmrtdTags.DGI_AA_KEY;
    /** DGI carrying the Chip Authentication static private scalar (32 bytes). */
    public static final short DGI_CA_KEY = EmrtdTags.DGI_CA_KEY;
    /** DGI carrying the PACE key seed SHA-1(MRZ_info) (20 bytes). */
    public static final short DGI_PACE_SEED = EmrtdTags.DGI_PACE_SEED;
    /** DGI carrying the PACE key seed SHA-1(CAN) (20 bytes, ref 0x02). */
    public static final short DGI_PACE_CAN_SEED = EmrtdTags.DGI_PACE_CAN_SEED;

    /** Largest key-DGI value: modLen(2) + 256 + expLen(2) + 256. */
    private static final short SCRATCH_SIZE = (short) 520;

    private static final byte MODE_NONE = 0;
    private static final byte MODE_FILE = 1;
    private static final byte MODE_IGNORE = 2;
    private static final byte MODE_SEED = 3;
    private static final byte MODE_AA = 4;
    private static final byte MODE_CA = 5;
    private static final byte MODE_PACE = 6;
    private static final byte MODE_MF = 7;
    private static final byte MODE_PACE_CAN = 8;

    private final LdsCatalog catalog;
    private final AaCrypto aa;
    private final ChipAuth chipAuth;
    private final PaceSeedSink pace;
    private final DgiStream stream;

    private final byte[] seed = new byte[16];
    /** The current key DGI's value (only one key DGI is ever in flight). */
    private final byte[] scratch = new byte[SCRATCH_SIZE];
    private short scratchLen;
    private byte mode;
    private LdsFile currentFile;
    /** Master-file EF.CardSecurity being streamed (DGI FF05). */
    private Lds2TransparentFile currentMf;
    private boolean seedSet;
    private boolean dg1Set;

    public LdsPerso(LdsCatalog catalog, AaCrypto aa, ChipAuth chipAuth, PaceSeedSink pace) {
        this.catalog = catalog;
        this.aa = aa;
        this.chipAuth = chipAuth;
        this.pace = pace;
        this.stream = new DgiStream(this);
    }

    /** The BAC K_seed written by the FF01 DGI. */
    public byte[] seed() {
        return seed;
    }

    public boolean seedSet() {
        return seedSet;
    }

    /** Starts a new personalization sequence. */
    public void reset() {
        stream.reset();
    }

    /** Feeds one STORE DATA payload (may span several DGIs). */
    public void feed(byte[] buf, short off, short len) {
        stream.feed(buf, off, len);
    }

    /** Applies the completion checks after the last STORE DATA block. */
    public void finish() {
        stream.finish();
    }

    /**
     * Applies a complete DGI sequence in one call (used by the unit tests and
     * by callers that already hold the whole sequence).
     */
    public void apply(byte[] buf, short off, short len) {
        stream.reset();
        stream.feed(buf, off, len);
        stream.finish();
    }

    // --- DgiStream.Sink ------------------------------------------------------

    public void onReset() {
        seedSet = false;
        dg1Set = false;
        mode = MODE_NONE;
        scratchLen = 0;
        currentFile = null;
        currentMf = null;
    }

    public void onBeginDgi(short dgi, short valueLength) {
        scratchLen = 0;
        if (dgi == DGI_SEED) {
            mode = MODE_SEED;
        } else if (dgi == DGI_AA_KEY) {
            mode = MODE_AA;
        } else if (dgi == DGI_CA_KEY) {
            mode = MODE_CA;
        } else if (dgi == DGI_PACE_SEED) {
            mode = MODE_PACE;
        } else if (dgi == DGI_PACE_CAN_SEED) {
            mode = MODE_PACE_CAN;
        } else if (dgi == EmrtdTags.DGI_CARD_SECURITY) {
            // EF.CardSecurity lives in the master file (Doc 9303-10 §3.11.4),
            // so it is streamed into the shared LdsMfStore, not the LDS1
            // catalog (where FID 011D is EF.SOD).
            mode = MODE_MF;
            currentMf = LdsMfStore.file(EmrtdTags.FID_CARD_SECURITY);
            currentMf.ensureCapacity(valueLength);
            currentMf.beginSet();
        } else {
            LdsFile file = catalog.file(dgi);
            if (file == null) {
                mode = MODE_IGNORE;
            } else {
                mode = MODE_FILE;
                currentFile = file;
                // The DGI header gave the value length up front, so the file
                // lays out its final page table once (docs/specs/emrtd/
                // emrtd.md §8).
                file.ensureCapacity(valueLength);
                file.beginSet();
                catalog.markPresent(dgi);
                if (dgi == EmrtdTags.FID_DG1) {
                    dg1Set = true;
                }
            }
        }
    }

    public void onData(byte[] buf, short off, short len) {
        if (mode == MODE_FILE) {
            currentFile.append(buf, off, len);
        } else if (mode == MODE_MF) {
            currentMf.append(buf, off, len);
        } else if (mode != MODE_IGNORE) {
            if (scratchLen > SCRATCH_SIZE || len > (short) (SCRATCH_SIZE - scratchLen)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Util.arrayCopyNonAtomic(buf, off, scratch, scratchLen, len);
            scratchLen = (short) (scratchLen + len);
        }
    }

    public void onEndDgi() {
        if (mode == MODE_SEED) {
            if (scratchLen != (short) 16) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            Util.arrayCopyNonAtomic(scratch, (short) 0, seed, (short) 0, (short) 16);
            seedSet = true;
        } else if (mode == MODE_AA) {
            setAaKey();
        } else if (mode == MODE_CA) {
            chipAuth.setPrivateKey(scratch, (short) 0, scratchLen);
        } else if (mode == MODE_PACE) {
            pace.setSeed(scratch, (short) 0, scratchLen);
        } else if (mode == MODE_PACE_CAN) {
            pace.setCanSeed(scratch, (short) 0, scratchLen);
        }
        mode = MODE_NONE;
        scratchLen = 0;
    }

    public void onFinish() {
        catalog.finalizeCatalog();
        if (!seedSet || !dg1Set) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    /**
     * The AA private key DGI is {@code modLen(2) || modulus || expLen(2) || exponent}
     * (the card stores both parts in one RSA private key object).
     */
    private void setAaKey() {
        if (scratchLen < (short) 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short modulusLength = Util.getShort(scratch, (short) 0);
        if (modulusLength <= 0 || modulusLength > (short) (scratchLen - 4)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short exponentLengthOffset = (short) (2 + modulusLength);
        short exponentLength = Util.getShort(scratch, exponentLengthOffset);
        short exponentOffset = (short) (exponentLengthOffset + 2);
        if (exponentLength <= 0
                || (short) (exponentOffset + exponentLength) != scratchLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        aa.setPrivateKey(scratch, (short) 2, modulusLength,
                scratch, exponentOffset, exponentLength);
    }
}
