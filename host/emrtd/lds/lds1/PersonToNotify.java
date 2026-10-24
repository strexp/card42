package card42.host.emrtd.lds.lds1;

import java.util.Map;

import card42.host.emrtd.lds.common.LdsBytes;
import card42.host.emrtd.lds.common.LdsDate;

/**
 * One person-to-notify template from DG16 (ICAO Doc 9303-10 §4.7.16,
 * Table 80): {@code A1..An { 5F50 date, 5F51 name, 5F52 telephone, 5F53 address }}.
 */
public final class PersonToNotify {

    /** The template tag (A1, A2, ...). */
    public final int templateTag;
    /** The date data recorded, or null when absent/invalid. */
    public final LdsDate dateRecorded;
    /** The raw date field, or null. */
    public final String dateRecordedRaw;
    public final String name;
    public final String telephone;
    public final String address;
    /** Unknown elements of the template, by tag. */
    public final Map<Integer, byte[]> unknown;
    /** The complete {@code Ax} template. */
    public final byte[] raw;

    PersonToNotify(int templateTag, LdsDate dateRecorded, String dateRecordedRaw, String name,
                   String telephone, String address, Map<Integer, byte[]> unknown, byte[] raw) {
        this.templateTag = templateTag;
        this.dateRecorded = dateRecorded;
        this.dateRecordedRaw = dateRecordedRaw;
        this.name = name;
        this.telephone = telephone;
        this.address = address;
        this.unknown = unknown;
        this.raw = LdsBytes.copy(raw);
    }
}
