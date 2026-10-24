package card42.test;

import java.util.List;

import card42.host.emrtd.lds.common.ImageData;
import card42.host.emrtd.lds.common.LdsIssue;
import card42.host.emrtd.lds.common.ParseStatus;
import card42.host.emrtd.lds.lds1.Dg2;
import card42.host.emrtd.lds.lds1.Dg3;
import card42.host.emrtd.lds.lds1.Dg4;
import card42.host.emrtd.lds.lds1.FaceImage;
import card42.host.emrtd.lds.lds1.FingerImage;
import card42.host.emrtd.lds.lds1.IrisImage;

/** DG2/DG3/DG4 (CBEFF + ISO/IEC 19794) parser tests. */
final class DgBiometricTest {

    private DgBiometricTest() {
    }

    static void run() {
        System.out.println("DgBiometric");
        dg2Face();
        dg2MultipleFaces();
        dg2LegacyBdb();
        dg3Finger();
        dg3Multiple();
        dg3Minutiae();
        dg4Iris();
        malformed();
    }

    private static void dg2Face() {
        byte[] jpeg = LdsFixtures.JPEG;
        Dg2 dg2 = Dg2.parse(LdsFixtures.dg2(jpeg));
        Asserts.eq(1, dg2.faces.size(), "DG2 has one face");
        Asserts.eq(ParseStatus.OK, dg2.status, "DG2 status");
        Asserts.bytes(jpeg, dg2.image, "DG2 image is the embedded JPEG");
        FaceImage face = dg2.faces.get(0);
        Asserts.eq(400, face.image.width, "DG2 width");
        Asserts.eq(500, face.image.height, "DG2 height");
        Asserts.eq(ImageData.Format.JPEG, face.image.format, "DG2 image format");
        Asserts.check(face.cbeff != null, "DG2 carries the CBEFF header");
        Asserts.eq(0x0008, face.cbeff.formatType, "DG2 CBEFF format type");
        Asserts.eq(0x0101, face.cbeff.formatOwner, "DG2 CBEFF format owner");
        Asserts.eq(2, face.cbeff.biometricType, "DG2 CBEFF biometric type");
        Asserts.check(dg2.issues.isEmpty(), "DG2 has no issues");
    }

    private static void dg2MultipleFaces() {
        Dg2 dg2 = Dg2.parse(LdsFixtures.dg2TwoTemplates(LdsFixtures.JPEG));
        Asserts.eq(2, dg2.faces.size(), "DG2 two templates yield two faces");
        Asserts.eq(2, dg2.declaredCount, "DG2 declared count");
        Asserts.eq(ParseStatus.OK, dg2.status, "DG2 two-template status");
        Asserts.bytes(LdsFixtures.JPEG, dg2.faces.get(1).image.bytes,
                "second DG2 face image");
    }

    private static void dg2LegacyBdb() {
        Dg2 dg2 = Dg2.parse(LdsFixtures.dg2Legacy());
        Asserts.eq(1, dg2.faces.size(), "legacy DG2 still finds the image");
        Asserts.eq(ParseStatus.PARTIAL, dg2.status, "legacy DG2 is partial");
        Asserts.check(hasCode(dg2.issues, LdsIssue.Code.UNSUPPORTED_LAYOUT),
                "legacy DG2 reports the missing ISO header");
        Asserts.bytes(LdsFixtures.JPEG, dg2.image, "legacy DG2 image");
    }

    private static void dg3Finger() {
        Dg3 dg3 = Dg3.parse(LdsFixtures.dg3());
        Asserts.eq(1, dg3.fingers.size(), "DG3 has one finger");
        Asserts.eq(ParseStatus.OK, dg3.status, "DG3 status");
        FingerImage finger = dg3.fingers.get(0);
        Asserts.eq(1, finger.position, "DG3 finger position");
        Asserts.eq("right thumb", FingerImage.positionName(finger.position),
                "DG3 finger position name");
        Asserts.eq(320, finger.image.width, "DG3 width");
        Asserts.eq(400, finger.image.height, "DG3 height");
        Asserts.eq(ImageData.Format.JPEG, finger.image.format, "DG3 image format");
        Asserts.bytes(LdsFixtures.JPEG, finger.image.bytes, "DG3 image bytes");
        Asserts.eq(80, finger.quality, "DG3 quality");
        Asserts.eq("FIR", finger.recordFormat, "DG3 record format");
    }

    private static void dg3Multiple() {
        Dg3 dg3 = Dg3.parse(LdsFixtures.dg3TwoTemplates());
        Asserts.eq(2, dg3.fingers.size(), "DG3 two templates yield two fingers");
        Asserts.eq(2, dg3.declaredCount, "DG3 declared count");
        Asserts.eq(ParseStatus.OK, dg3.status, "DG3 two-template status");
    }

    private static void dg3Minutiae() {
        Dg3 dg3 = Dg3.parse(LdsFixtures.dg3Minutiae());
        Asserts.eq(1, dg3.fingers.size(), "DG3 minutiae record is kept");
        Asserts.check(dg3.hasMinutiaeRecords, "DG3 flags a minutiae record");
        Asserts.eq("FMR", dg3.fingers.get(0).recordFormat, "DG3 record format is FMR");
        Asserts.check(dg3.fingers.get(0).image == null, "DG3 minutiae has no image");
        Asserts.check(dg3.fingers.get(0).raw.length > 0, "DG3 minutiae keeps the raw record");
    }

    private static void dg4Iris() {
        Dg4 dg4 = Dg4.parse(LdsFixtures.dg4());
        Asserts.eq(1, dg4.irises.size(), "DG4 has one iris");
        Asserts.eq(ParseStatus.OK, dg4.status, "DG4 status");
        IrisImage iris = dg4.irises.get(0);
        Asserts.eq(1, iris.eyePosition, "DG4 eye position");
        Asserts.eq("right", IrisImage.eyeName(iris.eyePosition), "DG4 eye name");
        Asserts.eq(640, iris.image.width, "DG4 width");
        Asserts.eq(ImageData.Format.JPEG, iris.image.format, "DG4 image format");
        Asserts.bytes(LdsFixtures.JPEG, iris.image.bytes, "DG4 image bytes");
    }

    private static void malformed() {
        byte[][] samples = {
                LdsFixtures.dg2(LdsFixtures.JPEG),
                LdsFixtures.dg2Legacy(),
                LdsFixtures.dg3(),
                LdsFixtures.dg3Minutiae(),
                LdsFixtures.dg4()
        };
        for (byte[] sample : samples) {
            for (byte[] truncated : LdsFixtures.truncations(sample)) {
                try {
                    if (sample[0] == 0x75) {
                        Dg2.parse(truncated);
                    } else if (sample[0] == 0x63) {
                        Dg3.parse(truncated);
                    } else {
                        Dg4.parse(truncated);
                    }
                    Asserts.check(true, "truncated biometric DG does not throw");
                } catch (RuntimeException e) {
                    Asserts.check(false, "truncated biometric DG threw " + e);
                }
            }
        }

        Dg2 empty = Dg2.parse(new byte[0]);
        Asserts.eq(ParseStatus.INVALID, empty.status, "empty DG2 is invalid");
        Asserts.check(empty.image == null, "empty DG2 has no image");

        Dg3 empty3 = Dg3.parse(new byte[0]);
        Asserts.eq(ParseStatus.INVALID, empty3.status, "empty DG3 is invalid");
        Dg4 empty4 = Dg4.parse(new byte[0]);
        Asserts.eq(ParseStatus.INVALID, empty4.status, "empty DG4 is invalid");

        // A declared count that does not match the templates is reported.
        byte[] wrongCount = LdsFixtures.tlv(0x75, LdsFixtures.tlv(0x7F61,
                LdsFixtures.tlv(0x02, new byte[] { 0x03 })));
        Dg2 count = Dg2.parse(wrongCount);
        Asserts.check(hasCode(count.issues, LdsIssue.Code.COUNT_MISMATCH),
                "DG2 count mismatch is reported");
    }

    private static boolean hasCode(List<LdsIssue> issues, LdsIssue.Code code) {
        for (LdsIssue issue : issues) {
            if (issue.code == code) {
                return true;
            }
        }
        return false;
    }
}
