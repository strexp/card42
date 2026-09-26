package card42.test;

import card42.emv.InstallParameters;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the install-parameter parsing and role fallback
 * (Java Card 3.0.5 JCRE §11.2.1): the (L,V) instance AID,
 * control info and applet data layout, the AID fallback match and the
 * applet-data role code with its fallback.
 *
 * <p>Platform coverage: Java Card JCRE §11.2.1 rather than an EMV/ICAO/BSI/CPS
 * clause.
 */
final class InstallParametersTest {

    private InstallParametersTest() {
    }

    static void run() {
        System.out.println("InstallParameters");

        // (L,V) instance AID || (L,V) control info || (L,V) applet data.
        byte[] params = {
                0x07, (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
                0x00, // empty control info
                0x01, 0x02 // applet data: role code 0x02
        };
        InstallParameters p = new InstallParameters();
        p.capture(params, (short) 0, (short) params.length);

        Asserts.check(p.instanceAidEquals(Hex.parse("A0000000031010")),
                "install AID fallback matches the captured instance AID");
        Asserts.check(!p.instanceAidEquals(Hex.parse("A0000000031011")),
                "install AID fallback rejects a different AID");
        Asserts.eq(1, p.getInstallDataLength(), "applet data length");
        Asserts.eq(0x02, p.getInstallData()[0] & 0xFF, "applet data first byte");

        // Role resolution from the applet data, with a fallback.
        Asserts.eq((byte) 0x11, p.roleFromInstallData((byte) 0x02, (byte) 0x11,
                        (byte) 0x01, (byte) 0x22, (byte) 0x33),
                "role code validA selects roleA");
        Asserts.eq((byte) 0x22, p.roleFromInstallData((byte) 0x09, (byte) 0x11,
                        (byte) 0x02, (byte) 0x22, (byte) 0x33),
                "role code validB selects roleB");
        Asserts.eq((byte) 0x33, p.roleFromInstallData((byte) 0x09, (byte) 0x11,
                        (byte) 0x08, (byte) 0x22, (byte) 0x33),
                "unknown role code falls back");

        // No applet data: the fallback is used and the AID still matches.
        byte[] noData = { 0x07, (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00 };
        InstallParameters q = new InstallParameters();
        q.capture(noData, (short) 0, (short) noData.length);
        Asserts.eq(0, q.getInstallDataLength(), "no applet data");
        Asserts.eq((byte) 0x33, q.roleFromInstallData((byte) 0x01, (byte) 0x11,
                        (byte) 0x02, (byte) 0x22, (byte) 0x33),
                "no applet data uses the fallback");
        Asserts.check(q.instanceAidEquals(Hex.parse("A0000000031010")),
                "AID still matches without applet data");
    }
}
