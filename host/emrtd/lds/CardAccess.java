package card42.host.emrtd.lds;

import java.util.ArrayList;
import java.util.List;

/**
 * EF.CardAccess: a DER SET OF SecurityInfo advertising the PACE and Chip
 * Authentication protocols supported by the chip (ICAO Doc 9303-10 §3.11.3,
 * Doc 9303-11 §3, H7.2).  The file is public (readable before authentication).
 */
public final class CardAccess {

    public final List<SecurityInfo> securityInfos;

    private CardAccess(List<SecurityInfo> securityInfos) {
        this.securityInfos = securityInfos;
    }

    public static CardAccess parse(byte[] cardAccess) {
        return new CardAccess(SecurityInfo.parseList(cardAccess));
    }

    /** All PACE protocol entries, in document order. */
    public List<PaceInfo> paceInfos() {
        List<PaceInfo> out = new ArrayList<PaceInfo>();
        for (SecurityInfo info : securityInfos) {
            if (info instanceof PaceInfo) {
                out.add((PaceInfo) info);
            }
        }
        return out;
    }

    /** All Chip Authentication protocol entries, in document order. */
    public List<ChipAuthenticationInfo> chipAuthenticationInfos() {
        List<ChipAuthenticationInfo> out = new ArrayList<ChipAuthenticationInfo>();
        for (SecurityInfo info : securityInfos) {
            if (info instanceof ChipAuthenticationInfo) {
                out.add((ChipAuthenticationInfo) info);
            }
        }
        return out;
    }

    /**
     * Selects the first supported PACE protocol: ECDH generic mapping when
     * present, else DH generic mapping, else null (the PACE protocol itself is
     * not run here).
     */
    public PaceInfo selectPace() {
        List<PaceInfo> infos = paceInfos();
        for (PaceInfo info : infos) {
            if (info.isEcdhGenericMapping()) {
                return info;
            }
        }
        for (PaceInfo info : infos) {
            if (info.isDhGenericMapping()) {
                return info;
            }
        }
        return infos.isEmpty() ? null : infos.get(0);
    }
}
