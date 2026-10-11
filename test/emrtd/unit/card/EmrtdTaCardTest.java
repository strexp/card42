package card42.test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.security.SecureRandom;

import card42.emrtd.EmrtdApplet;
import card42.emrtd.EmrtdInstallParameters;
import card42.emrtd.EmrtdTags;
import card42.emrtd.LdsPerso;
import card42.emrtd.Mse;
import card42.emrtd.PsoVerifyCertificate;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.ta.TaChain;

/**
 * Card-side Terminal Authentication certificate verification (P3): drives
 * {@code Mse.process} (0x81B6) and {@code PsoVerifyCertificate.process}
 * (2A/00BE) on a real LDS1 {@link EmrtdApplet} against a host-issued CV
 * certificate chain, with the CVCA trust point set through the FF07
 * personalization DGI.  The ECDSA-SHA-256 plain verification runs on the
 * JCE-backed {@code Signature} stub, so the card's key import and status words
 * are checked without a simulator.
 *
 * <p>Spec: ICAO Doc 9303-11 §7.1.5.1/§7.1.5.2, BSI TR-03110-3 A.7.2.
 */
final class EmrtdTaCardTest {

    private EmrtdTaCardTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdTaCard");
        verifyChain();
        rejectsTamperedCertificate();
        rejectsUnknownReference();
        rejectsWithoutTrustPoint();
    }

    private static void verifyChain() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);

        for (byte[] encoded : chain.toSend()) {
            CvCertificate certificate = CvCertificateCodec.parse(encoded);
            byte[] dst = mseSetDst(certificate);
            byte[] pso = pso(certificate);
            Asserts.noThrow(() -> Mse.process(applet, (byte) 0x81, (byte) 0xB6,
                            dst, (short) 0, (short) dst.length),
                    "MSE:Set DST accepts " + certificate.certificateHolderReference());
            Asserts.noThrow(() -> PsoVerifyCertificate.process(applet, pso,
                            (short) 0, (short) pso.length),
                    "PSO:Verify Certificate imports " + certificate.certificateHolderReference());
        }
    }

    private static void rejectsTamperedCertificate() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);

        byte[] tampered = chain.dv.encoded().clone();
        tampered[tampered.length - 1] ^= 0x01;
        CvCertificate certificate = CvCertificateCodec.parse(tampered);
        byte[] dst = mseSetDst(certificate);
        byte[] pso = pso(certificate);
        Asserts.sw((short) 0x6A80, () -> {
            Mse.process(applet, (byte) 0x81, (byte) 0xB6, dst, (short) 0, (short) dst.length);
            PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
        }, "a tampered CV certificate -> 6A80");
    }

    private static void rejectsUnknownReference() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);

        // MSE:Set DST accepts an unavailable reference; PSO rejects it with 6A88
        // (ICAO Doc 9303-11 §7.1.5.1 note).
        byte[] unknown = "ZZUNKNOWN0000000".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] certificate = chain.dv.encoded();
        byte[] pso = pso(CvCertificateCodec.parse(certificate));
        Asserts.sw((short) 0x6A88, () -> {
            Mse.process(applet, (byte) 0x81, (byte) 0xB6,
                    mseSetDstRef(unknown), (short) 0, (short) mseSetDstRef(unknown).length);
            PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
        }, "PSO:Verify Certificate with an unknown reference -> 6A88");
    }

    private static void rejectsWithoutTrustPoint() throws Exception {
        EmrtdApplet applet = lds1Applet();
        byte[] reference = "UTREF000000000000".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        Asserts.sw((short) 0x6985, () -> Mse.process(applet, (byte) 0x81, (byte) 0xB6,
                        mseSetDstRef(reference), (short) 0, (short) mseSetDstRef(reference).length),
                "MSE:Set DST without a trust point -> 6985");
    }

    // --- helpers -------------------------------------------------------------

    /** Writes the CVCA trust point DGI (FF07 = W(65) || refLen(1) || CAR). */
    private static void setTrustPoint(EmrtdApplet applet, TaChain.Chain chain) throws Exception {
        byte[] cvcaW = chain.cvca.ecPublicKey();
        byte[] car = chain.cvca.certificateHolderReference().encode();
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(cvcaW, 0, cvcaW.length);
        value.write(car.length);
        value.write(car, 0, car.length);

        // A minimal valid LDS1 sequence: BAC seed + DG1 + the trust point, so
        // the perso completion check (seed and DG1 required) passes.
        ByteArrayOutputStream sequence = new ByteArrayOutputStream();
        writeDgi(sequence, EmrtdTags.DGI_BAC_SEED, new byte[16]);
        writeDgi(sequence, EmrtdTags.FID_DG1, new byte[] { 0x61, 0x03, 0x5F, 0x1F, 0x00 });
        writeDgi(sequence, EmrtdTags.DGI_TA_TRUST_POINT, value.toByteArray());
        byte[] bytes = sequence.toByteArray();

        Field field = EmrtdApplet.class.getDeclaredField("perso");
        field.setAccessible(true);
        LdsPerso perso = (LdsPerso) field.get(applet);
        perso.apply(bytes, (short) 0, (short) bytes.length);
    }

    private static byte[] mseSetDst(CvCertificate certificate) {
        return mseSetDstRef(certificate.certificationAuthorityReference().encode());
    }

    private static byte[] mseSetDstRef(byte[] reference) {
        return doTag(0x83, reference);
    }

    private static byte[] pso(CvCertificate certificate) {
        return concat(certificate.body(), CvCertificateCodec.signatureTlv(certificate.signature()));
    }

    private static byte[] doTag(int tag, byte[] value) {
        byte[] out = new byte[2 + value.length];
        out[0] = (byte) tag;
        out[1] = (byte) value.length;
        System.arraycopy(value, 0, out, 2, value.length);
        return out;
    }

    private static void writeDgi(ByteArrayOutputStream out, short dgi, byte[] value) {
        out.write((dgi >> 8) & 0xFF);
        out.write(dgi & 0xFF);
        out.write(value.length);
        out.write(value, 0, value.length);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static EmrtdApplet lds1Applet() throws Exception {
        Constructor<EmrtdApplet> ctor = EmrtdApplet.class.getDeclaredConstructor(
                byte.class, byte[].class, short.class);
        ctor.setAccessible(true);
        return ctor.newInstance(EmrtdInstallParameters.ROLE_LDS1,
                EmrtdTags.DF_NAME_LDS1, (short) EmrtdTags.DF_NAME_LDS1.length);
    }
}
