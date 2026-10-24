package card42.host.emrtd.lds.common;

import java.util.List;

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
import card42.host.emrtd.lds.lds1.Dg;

/**
 * The common surface of a parsed LDS1 data group (ICAO Doc 9303-10 §4.7):
 * its number, the raw EF, and the status/issues of the field model.
 *
 * <p>Every data problem is reported through {@link #issues()}; the raw EF is
 * always available so a caller can fall back to a hexadecimal or TLV view.
 * The interface is deliberately not sealed: the concrete groups live in
 * {@code lds.lds1} and a jar on the class path is in the unnamed module, where
 * a sealed interface cannot permit subclasses from another package.
 */
public interface LdsDataGroup {

    /** The data group number (1..16), or 0 when the outer tag is unknown. */
    int dg();

    /** The complete raw EF, including the outer tag, as a fresh copy. */
    byte[] raw();

    ParseStatus status();

    /** The observations collected while parsing; immutable. */
    List<LdsIssue> issues();

    /**
     * Parses data group {@code dg} and returns the model with the raw bytes.
     * Data problems never throw; a structurally unreadable EF yields an
     * {@link ParseStatus#INVALID} result whose {@code value} carries the raw
     * bytes (or is null for a completely empty EF).
     */
    static LdsParseResult<LdsDataGroup> parse(int dg, byte[] raw) {
        LdsDataGroup value;
        switch (dg) {
        case 1:
            value = Dg1.parse(raw);
            break;
        case 2:
            value = Dg2.parse(raw);
            break;
        case 3:
            value = Dg3.parse(raw);
            break;
        case 4:
            value = Dg4.parse(raw);
            break;
        case 5:
            value = Dg5.parse(raw);
            break;
        case 7:
            value = Dg7.parse(raw);
            break;
        case 8:
            value = Dg8.parse(raw);
            break;
        case 9:
            value = Dg9.parse(raw);
            break;
        case 10:
            value = Dg10.parse(raw);
            break;
        case 11:
            value = Dg11.parse(raw);
            break;
        case 12:
            value = Dg12.parse(raw);
            break;
        case 13:
            value = Dg13.parse(raw);
            break;
        case 16:
            value = Dg16.parse(raw);
            break;
        default:
            // DG6 is reserved and DG14/DG15 are security objects parsed by
            // their dedicated classes; the generic view keeps raw + TLV access.
            value = Dg.parse(raw);
            break;
        }
        return new LdsParseResult<LdsDataGroup>(value, value.status(), value.issues(), raw);
    }
}
