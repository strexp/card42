package card42.test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import card42.emrtd.EmrtdApplet;
import card42.emrtd.EmrtdInstallParameters;
import card42.emrtd.EmrtdTags;
import card42.emrtd.ExternalAuthenticate;
import card42.emrtd.GetChallenge;
import card42.emrtd.Lds2Perso;
import card42.emrtd.Lds2Record;
import card42.emrtd.LdsPerso;
import card42.emrtd.Mse;
import card42.emrtd.PsoVerifyCertificate;
import card42.emrtd.ReadBinary;
import card42.emrtd.TaContext;
import card42.host.common.crypto.Ecdsa;
import card42.host.common.crypto.P256;
import card42.host.common.crypto.RsaPss;
import card42.host.emrtd.ta.Chat;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateBuilder;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.ta.CvcPrincipal;
import card42.host.emrtd.ta.TaChain;

/**
 * Card-side Terminal Authentication: P3 certificate-chain verification and P4
 * the EXTERNAL AUTHENTICATE step, driven on a real LDS1 {@link EmrtdApplet}
 * against a host-issued CV certificate chain.  The CVCA trust point is set
 * through the FF07 personalization DGI and the PACE/CA key hashes are injected
 * directly (the PACE and Chip Authentication protocols are covered by their own
 * simulator suites).  ECDSA-SHA-256 plain verification runs on the JCE-backed
 * {@code Signature} stub.
 *
 * <p>Spec: ICAO Doc 9303-11 §7.1.5, BSI TR-03110-3 A.7.
 */
final class EmrtdTaCardTest {

    private EmrtdTaCardTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdTaCard");
        // The TA state is package-shared, so this must run before any test sets a
        // trust point.
        rejectsWithoutTrustPoint();
        verifyChain();
        rejectsTamperedCertificate();
        rejectsUnknownReference();
        fullTerminalAuthentication();
        rejectsBadTerminalSignature();
        rejectsExternalAuthenticateWithoutMseAt();
        travelAuthorization();
        travelCertificatesBits();
        currentDateMechanism();
        twoTrustPoints();
        trustPointEffectiveDate();
        cvcaLink();
        dg3Dg4Gating();
        rsaTerminalAuthentication();
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

    private static void fullTerminalAuthentication() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);
        importChain(applet, chain);

        byte[] idIc = filled(32, (byte) 0x11);
        byte[] caKeyHash = filled(32, (byte) 0x22);
        TaContext ta = taOf(applet);
        ta.notePiccEphemeral(uncompressed(idIc), (short) 0, (short) 65);
        ta.noteTerminalEphemeral(uncompressed(caKeyHash), (short) 0, (short) 65);

        byte[] at = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Asserts.noThrow(() -> Mse.process(applet, (byte) 0x81, (byte) 0xA4,
                        at, (short) 0, (short) at.length),
                "MSE:Set AT selects the terminal key");
        Asserts.noThrow(() -> GetChallenge.process(applet), "GET CHALLENGE returns rIC");

        byte[] challenge = (byte[]) field(TaContext.class, "challenge").get(ta);
        byte[] input = concat(idIc, challenge, caKeyHash);
        byte[] signature = Ecdsa.sign(input, chain.terminalPrivateScalar, new SecureRandom());
        Asserts.noThrow(() -> ExternalAuthenticate.process(applet, signature,
                        (short) 0, (short) signature.length),
                "EXTERNAL AUTHENTICATE accepts the terminal signature");
        Asserts.check((Boolean) field(TaContext.class, "taDone").get(ta),
                "terminal authentication completed");

        // A second Terminal Authentication in the same session is refused.
        byte[] at2 = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Asserts.sw((short) 0x6982, () -> Mse.process(applet, (byte) 0x81, (byte) 0xA4,
                        at2, (short) 0, (short) at2.length),
                "a second MSE:Set AT -> 6982");
    }

    private static void rejectsBadTerminalSignature() throws Exception {
        EmrtdApplet applet = lds1Applet();
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        setTrustPoint(applet, chain);
        importChain(applet, chain);

        byte[] idIc = filled(32, (byte) 0x11);
        byte[] caKeyHash = filled(32, (byte) 0x22);
        TaContext ta = taOf(applet);
        ta.notePiccEphemeral(uncompressed(idIc), (short) 0, (short) 65);
        ta.noteTerminalEphemeral(uncompressed(caKeyHash), (short) 0, (short) 65);

        byte[] at = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Mse.process(applet, (byte) 0x81, (byte) 0xA4, at, (short) 0, (short) at.length);
        GetChallenge.process(applet);
        byte[] challenge = (byte[]) field(TaContext.class, "challenge").get(ta);
        byte[] signature = Ecdsa.sign(concat(idIc, challenge, caKeyHash),
                chain.terminalPrivateScalar, new SecureRandom());
        signature[0] ^= 0x01;
        Asserts.sw((short) 0x6300, () -> ExternalAuthenticate.process(applet, signature,
                        (short) 0, (short) signature.length),
                "a bad terminal signature -> 6300");
    }

    private static void rejectsExternalAuthenticateWithoutMseAt() throws Exception {
        EmrtdApplet applet = lds1Applet();
        setTrustPoint(applet, TaChain.create(new SecureRandom()));
        byte[] signature = new byte[64];
        // Without MSE:Set AT the command falls through to the BAC path, which
        // rejects a 64-byte body with 6700 (wrong length).
        Asserts.sw((short) 0x6700, () -> ExternalAuthenticate.process(applet, signature,
                        (short) 0, (short) signature.length),
                "EXTERNAL AUTHENTICATE without MSE:Set AT -> BAC path 6700");
    }

    // --- helpers -------------------------------------------------------------

    /** Two CVCA trust points: a certificate signed by either one verifies. */
    private static void twoTrustPoints() throws Exception {
        EmrtdApplet applet = lds1Applet();
        resetTaState(applet);
        SecureRandom random = new SecureRandom();
        BigInteger a = P256.randomScalar(random);
        BigInteger b = P256.randomScalar(random);
        byte[] aw = P256.encode(P256.scalarMult(a, P256.generator()));
        byte[] bw = P256.encode(P256.scalarMult(b, P256.generator()));
        CvcPrincipal ar = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal br = CvcPrincipal.of("UTCVCA0000000002");
        CvcPrincipal dr1 = CvcPrincipal.of("UTDV000000000003");
        CvcPrincipal dr2 = CvcPrincipal.of("UTDV000000000004");
        java.util.Map<String, byte[]> noAuth = new java.util.LinkedHashMap<String, byte[]>();

        setTrustPoint(applet, EmrtdTags.DGI_TA_TRUST_POINT, aw, ar.encode(),
                new byte[] { 0x03, 0, 0, 0 });
        setTrustPoint(applet, EmrtdTags.DGI_TA_TRUST_POINT_2, bw, br.encode(),
                new byte[] { 0x03, 0, 0, 0 });

        byte[] dvW1 = P256.encode(P256.scalarMult(P256.randomScalar(random), P256.generator()));
        byte[] dvW2 = P256.encode(P256.scalarMult(P256.randomScalar(random), P256.generator()));
        CvCertificate bySecondary = CvCertificateBuilder.build(0, br, dr1, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, dvW1, "250101", "300101", noAuth, b, random);
        CvCertificate byPrimary = CvCertificateBuilder.build(0, ar, dr2, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, dvW2, "250101", "300101", noAuth, a, random);
        Asserts.noThrow(() -> importCert(applet, bySecondary),
                "a certificate signed by the secondary CVCA verifies");
        Asserts.noThrow(() -> importCert(applet, byPrimary),
                "a certificate signed by the primary CVCA verifies");
    }

    /**
     * Trust-point Effective Dates (ICAO Doc 9303-11 §7.1.4.3.1): a trust point
     * whose Effective Date has not yet been reached is not usable for
     * certificate verification.
     */
    private static void trustPointEffectiveDate() throws Exception {
        EmrtdApplet applet = lds1Applet();
        resetTaState(applet);
        SecureRandom random = new SecureRandom();
        BigInteger a = P256.randomScalar(random);
        BigInteger b = P256.randomScalar(random);
        byte[] aw = P256.encode(P256.scalarMult(a, P256.generator()));
        byte[] bw = P256.encode(P256.scalarMult(b, P256.generator()));
        CvcPrincipal ar = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal br = CvcPrincipal.of("UTCVCA0000000002");
        CvcPrincipal dr1 = CvcPrincipal.of("UTDV000000000003");
        CvcPrincipal dr2 = CvcPrincipal.of("UTDV000000000004");
        byte[] auth = { 0x03, 0, 0, 0 };
        java.util.Map<String, byte[]> noAuth = new java.util.LinkedHashMap<String, byte[]>();

        // ICC current date 240101; primary effective 240101, secondary 250101.
        setTrustPointEffective(applet, EmrtdTags.DGI_TA_TRUST_POINT, aw, ar.encode(),
                "240101", auth);
        setTrustPointEffective(applet, EmrtdTags.DGI_TA_TRUST_POINT_2, bw, br.encode(),
                "250101", auth);
        personalizeDate(applet, "240101");

        byte[] dvW1 = P256.encode(P256.scalarMult(P256.randomScalar(random), P256.generator()));
        CvCertificate byPrimary = CvCertificateBuilder.build(0, ar, dr1, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, dvW1, "240101", "300101", noAuth, a, random);
        Asserts.noThrow(() -> importCert(applet, byPrimary),
                "a reached Effective Date trust point verifies");

        byte[] dvW2 = P256.encode(P256.scalarMult(P256.randomScalar(random), P256.generator()));
        CvCertificate byFuture = CvCertificateBuilder.build(0, br, dr2, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, dvW2, "250101", "300101", noAuth, b, random);
        Asserts.sw((short) 0x6A88, () -> importCert(applet, byFuture),
                "a not-yet-reached Effective Date trust point -> 6A88");
    }

    /** Writes a trust-point DGI with an explicit Effective Date (new layout). */
    private static void setTrustPointEffective(EmrtdApplet applet, short dgi, byte[] w,
                                               byte[] car, String effective, byte[] auth)
            throws Exception {
        ByteArrayOutputStream dgis = new ByteArrayOutputStream();
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(w, 0, w.length);
        value.write(car.length);
        value.write(car, 0, car.length);
        byte[] date = new byte[6];
        for (int i = 0; i < 6; i++) {
            date[i] = (byte) (effective.charAt(i) - '0');
        }
        value.write(date, 0, 6);
        value.write(auth, 0, auth.length);
        writeDgi(dgis, dgi, value.toByteArray());
        applyLds1(applet, dgis);
    }

    /** A CVCA Link Certificate adds a trust point, activated by its Effective Date. */
    private static void cvcaLink() throws Exception {        EmrtdApplet applet = lds1Applet();
        resetTaState(applet);
        SecureRandom random = new SecureRandom();
        BigInteger a = P256.randomScalar(random);
        BigInteger b = P256.randomScalar(random);
        BigInteger dv = P256.randomScalar(random);
        byte[] aw = P256.encode(P256.scalarMult(a, P256.generator()));
        byte[] bw = P256.encode(P256.scalarMult(b, P256.generator()));
        byte[] dvW = P256.encode(P256.scalarMult(dv, P256.generator()));
        CvcPrincipal ar = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal br = CvcPrincipal.of("UTCVCA0000000002");
        CvcPrincipal dr = CvcPrincipal.of("UTDV000000000003");
        java.util.Map<String, byte[]> noAuth = new java.util.LinkedHashMap<String, byte[]>();

        setTrustPoint(applet, EmrtdTags.DGI_TA_TRUST_POINT, aw, ar.encode(),
                new byte[] { 0x03, 0, 0, 0 });
        personalizeDate(applet, "240101");

        // The new CVCA (B) is unknown before the link.
        CvCertificate byLink = CvCertificateBuilder.build(0, br, dr, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, dvW, "250201", "300101", noAuth, b, random);
        byte[] dstB = doTag(0x83, br.encode());
        Asserts.sw((short) 0x6A88, () -> {
            Mse.process(applet, (byte) 0x81, (byte) 0xB6, dstB, (short) 0, (short) dstB.length);
            byte[] pso = pso(byLink);
            PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
        }, "a certificate of an unlinked CVCA -> 6A88");

        // The CVCA Link Certificate (role CVCA), signed by A, is effective 250101.
        CvCertificate link = CvCertificateBuilder.build(0, ar, br, Chat.Role.CVCA,
                new byte[] { (byte) 0x03 }, bw, "250101", "300101", noAuth, a, random);
        importCert(applet, link);
        TaContext ta = taOf(applet);
        Asserts.bytes(new byte[] { 2, 5, 0, 1, 0, 1 },
                (byte[]) field(TaContext.class, "currentDate").get(ta),
                "the CVCA Link Effective Date advances the current date");

        // The linked CVCA (B) now verifies its own certificates.
        Asserts.noThrow(() -> importCert(applet, byLink),
                "a certificate signed by the linked CVCA verifies");
    }

    /** LDS1 DG3/DG4 read requires the ePassport CHAT bit once a trust point exists. */
    private static void dg3Dg4Gating() throws Exception {
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        byte[] dg3 = { 0x63, 0x02, 0x11, 0x22 };
        byte[] dg4 = { 0x76, 0x02, 0x33, 0x44 };

        EmrtdApplet granted = lds1Applet();
        resetTaState(granted);
        setTrustPointWithDg(granted, chain, EmrtdTags.FID_DG3, dg3, new byte[] { 0x03, 0, 0, 0 });
        field(EmrtdApplet.class, "smEstablished").setBoolean(granted, true);
        field(EmrtdApplet.class, "paceDone").setBoolean(granted, true);
        byte[] apdu3 = readApdu((byte) 0x83);
        Asserts.sw((short) 0x6982,
                () -> ReadBinary.process(granted, (short) 0xE7, apdu3),
                "DG3 read before Terminal Authentication -> 6982");
        authenticateTerminal(granted, chain);
        Asserts.noThrow(() -> ReadBinary.process(granted, (short) 0xE7, apdu3),
                "DG3 read after Terminal Authentication with the ePassport bit");

        // A trust point without the DG4 bit refuses EF.DG4.
        EmrtdApplet denied = lds1Applet();
        resetTaState(denied);
        setTrustPointWithDg(denied, chain, EmrtdTags.FID_DG4, dg4, new byte[] { 0x01, 0, 0, 0 });
        field(EmrtdApplet.class, "smEstablished").setBoolean(denied, true);
        field(EmrtdApplet.class, "paceDone").setBoolean(denied, true);
        authenticateTerminal(denied, chain);
        byte[] apdu4 = readApdu((byte) 0x84);
        Asserts.sw((short) 0x6982,
                () -> ReadBinary.process(denied, (short) 0xE7, apdu4),
                "DG4 read without the DG4 bit -> 6982");
    }

    /** RSA-PSS-SHA-256 terminal certificate and terminal signature. */
    private static void rsaTerminalAuthentication() throws Exception {
        EmrtdApplet applet = lds1Applet();
        resetTaState(applet);
        SecureRandom random = new SecureRandom();
        BigInteger cvca = P256.randomScalar(random);
        BigInteger dv = P256.randomScalar(random);
        byte[] cvcaW = P256.encode(P256.scalarMult(cvca, P256.generator()));
        byte[] dvW = P256.encode(P256.scalarMult(dv, P256.generator()));
        CvcPrincipal cvcaRef = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal dvRef = CvcPrincipal.of("UTDV000000000002");
        CvcPrincipal isRef = CvcPrincipal.of("UTIS000000000003");
        java.util.Map<String, byte[]> noAuth = new java.util.LinkedHashMap<String, byte[]>();

        setTrustPoint(applet, EmrtdTags.DGI_TA_TRUST_POINT, cvcaW, cvcaRef.encode(),
                new byte[] { 0x03, 0, 0, 0 });
        CvCertificate dvCert = CvCertificateBuilder.build(0, cvcaRef, dvRef,
                Chat.Role.DV_DOMESTIC, new byte[] { (byte) 0x03 }, dvW, "250101", "300101",
                noAuth, cvca, random);
        importCert(applet, dvCert);

        java.security.KeyPair rsa = rsaKeyPair();
        byte[] mod = RsaPss.unsigned(
                ((java.security.interfaces.RSAPublicKey) rsa.getPublic()).getModulus());
        byte[] exp = RsaPss.unsigned(
                ((java.security.interfaces.RSAPublicKey) rsa.getPublic()).getPublicExponent());
        byte[] body = CvCertificateCodec.encodeBodyRsa(0, dvRef,
                CvCertificate.OID_TA_RSA_PSS_SHA_256, mod, exp, isRef, Chat.Role.IS,
                new byte[] { (byte) 0x03 }, "250101", "300101", noAuth);
        CvCertificate terminal = CvCertificateCodec.parse(
                CvCertificateCodec.encode(body, Ecdsa.sign(body, dv, random)));
        importCert(applet, terminal);

        byte[] idIc = filled(32, (byte) 0x11);
        byte[] caKeyHash = filled(32, (byte) 0x22);
        TaContext ta = taOf(applet);
        ta.notePiccEphemeral(uncompressed(idIc), (short) 0, (short) 65);
        ta.noteTerminalEphemeral(uncompressed(caKeyHash), (short) 0, (short) 65);
        byte[] at = doTag(0x83, terminal.certificateHolderReference().encode());
        Mse.process(applet, (byte) 0x81, (byte) 0xA4, at, (short) 0, (short) at.length);
        GetChallenge.process(applet);
        byte[] challenge = (byte[]) field(TaContext.class, "challenge").get(ta);
        byte[] signature = RsaPss.sign(concat(idIc, challenge, caKeyHash), rsa.getPrivate());
        Asserts.eq(256, signature.length, "RSA-PSS terminal signature is the modulus length");
        Asserts.noThrow(() -> ExternalAuthenticate.process(applet, signature,
                        (short) 0, (short) signature.length),
                "EXTERNAL AUTHENTICATE accepts the RSA-PSS terminal signature");
        Asserts.check((Boolean) field(TaContext.class, "taDone").get(ta),
                "RSA terminal authentication completed");
    }

    /** A one-DGI trust-point sequence with the given holder authorization. */
    private static void setTrustPoint(EmrtdApplet applet, short dgi, byte[] w, byte[] car,
                                      byte[] auth) throws Exception {
        ByteArrayOutputStream dgis = new ByteArrayOutputStream();
        addTrustPointDgi(dgis, dgi, w, car, auth);
        applyLds1(applet, dgis);
    }

    /** Personalizes the current date (DGI FF08) in its own sequence. */
    private static void personalizeDate(EmrtdApplet applet, String date) throws Exception {
        ByteArrayOutputStream dgis = new ByteArrayOutputStream();
        byte[] value = new byte[6];
        for (int i = 0; i < 6; i++) {
            value[i] = (byte) (date.charAt(i) - '0');
        }
        writeDgi(dgis, EmrtdTags.DGI_TA_CURRENT_DATE, value);
        applyLds1(applet, dgis);
    }

    /** The trust point plus one DG EF, so the LDS1 CHAT gate can be exercised. */
    private static void setTrustPointWithDg(EmrtdApplet applet, TaChain.Chain chain,
                                            short fid, byte[] content, byte[] auth)
            throws Exception {
        ByteArrayOutputStream dgis = new ByteArrayOutputStream();
        addTrustPointDgi(dgis, EmrtdTags.DGI_TA_TRUST_POINT, chain.cvca.ecPublicKey(),
                chain.cvca.certificateHolderReference().encode(), auth);
        writeDgi(dgis, fid, content);
        applyLds1(applet, dgis);
    }

    /** Runs MSE:Set DST + PSO:Verify Certificate for one certificate. */
    private static void importCert(EmrtdApplet applet, CvCertificate certificate) {
        byte[] dst = doTag(0x83, certificate.certificationAuthorityReference().encode());
        Mse.process(applet, (byte) 0x81, (byte) 0xB6, dst, (short) 0, (short) dst.length);
        byte[] pso = pso(certificate);
        PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
    }

    /** A READ BINARY command APDU for the DG with the given SFI-form P1. */
    private static byte[] readApdu(byte p1) {
        byte[] apdu = new byte[5];
        apdu[0] = 0x0C; // rule C: secure messaging active
        apdu[2] = p1;
        apdu[3] = 0x00;
        return apdu;
    }

    /** Clears the package-shared trust points and the session state. */
    private static void resetTaState(EmrtdApplet applet) throws Exception {
        byte[] kinds = (byte[]) field(TaContext.class, "trustKind").get(null);
        kinds[0] = 0;
        kinds[1] = 0;
        field(TaContext.class, "currentDateValid").setBoolean(null, false);
        taOf(applet).clearSession();
    }

    /** Writes a trust-point DGI (FF07 / FF09) into the sequence builder. */
    private static void addTrustPointDgi(ByteArrayOutputStream out, short dgi, byte[] w,
                                         byte[] car, byte[] auth) {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(w, 0, w.length);
        value.write(car.length);
        value.write(car, 0, car.length);
        if (auth != null) {
            value.write(auth, 0, auth.length);
        }
        writeDgi(out, dgi, value.toByteArray());
    }

    /** Applies a DGI sequence to the LDS1 perso, always carrying the BAC seed and DG1. */
    private static void applyLds1(EmrtdApplet applet, ByteArrayOutputStream dgis)
            throws Exception {
        ByteArrayOutputStream sequence = new ByteArrayOutputStream();
        writeDgi(sequence, EmrtdTags.DGI_BAC_SEED, new byte[16]);
        writeDgi(sequence, EmrtdTags.FID_DG1, new byte[] { 0x61, 0x03, 0x5F, 0x1F, 0x00 });
        byte[] extra = dgis.toByteArray();
        sequence.write(extra, 0, extra.length);
        byte[] bytes = sequence.toByteArray();
        Field field = EmrtdApplet.class.getDeclaredField("perso");
        field.setAccessible(true);
        LdsPerso perso = (LdsPerso) field.get(applet);
        perso.apply(bytes, (short) 0, (short) bytes.length);
    }

    private static java.security.KeyPair rsaKeyPair() throws Exception {
        java.security.KeyPairGenerator generator =
                java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /**
     * LDS2 authorization gating (Doc 9303-10 §5.4): with the Travel
     * authorization bit the record EF is reachable; without it the read is
     * refused with 6982 even after a successful Terminal Authentication.
     */
    private static void travelAuthorization() throws Exception {
        TaChain.Chain chain = TaChain.create(new SecureRandom());

        EmrtdApplet granted = travelApplet();
        setTravelTrustPoint(granted, chain, (byte) 0x0F);
        authenticateTerminal(granted, chain);
        Asserts.sw((short) 0x6A83,
                () -> Lds2Record.readRecord(granted, (byte) 1, (byte) 0x0C, (short) 0),
                "granted LDS2 read reaches the record EF (no records -> 6A83)");

        EmrtdApplet denied = travelApplet();
        setTravelTrustPoint(denied, chain, (byte) 0x00);
        authenticateTerminal(denied, chain);
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.readRecord(denied, (byte) 1, (byte) 0x0C, (short) 0),
                "LDS2 read without the Travel authorization -> 6982");
    }

    /**
     * Travel/Visa EF.Certificates use b3 (read) / b4 (append) while
     * EF.EntryRecords/ExitRecords use b1/b2 (ICAO Doc 9303-10 §5.4.2 Table 96/97).
     * P2 in READ RECORD is {@code sfi << 3 | 0b100}: SFI 0x1A = EF.Certificates,
     * SFI 0x01 = EF.EntryRecords.
     */
    private static void travelCertificatesBits() throws Exception {
        TaChain.Chain chain = TaChain.create(new SecureRandom());

        // Only b3 (read EF.Certificates): Certificates reachable, records denied.
        EmrtdApplet certOnly = travelApplet();
        setTravelTrustPoint(certOnly, chain, (byte) 0x04);
        authenticateTerminal(certOnly, chain);
        Asserts.sw((short) 0x6A83,
                () -> Lds2Record.readRecord(certOnly, (byte) 1, (byte) 0xD4, (short) 0),
                "b3 grants EF.Certificates read (no records -> 6A83)");
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.readRecord(certOnly, (byte) 1, (byte) 0x0C, (short) 0),
                "b3 does not grant EF.EntryRecords read -> 6982");

        // Only b1 (read EF.EntryRecords): records reachable, Certificates denied.
        EmrtdApplet recordsOnly = travelApplet();
        setTravelTrustPoint(recordsOnly, chain, (byte) 0x01);
        authenticateTerminal(recordsOnly, chain);
        Asserts.sw((short) 0x6A83,
                () -> Lds2Record.readRecord(recordsOnly, (byte) 1, (byte) 0x0C, (short) 0),
                "b1 grants EF.EntryRecords read (no records -> 6A83)");
        Asserts.sw((short) 0x6982,
                () -> Lds2Record.readRecord(recordsOnly, (byte) 1, (byte) 0xD4, (short) 0),
                "b1 does not grant EF.Certificates read -> 6982");
    }

    private static void authenticateTerminal(EmrtdApplet applet, TaChain.Chain chain)
            throws Exception {
        importChain(applet, chain);
        byte[] idIc = filled(32, (byte) 0x11);
        byte[] caKeyHash = filled(32, (byte) 0x22);
        TaContext ta = taOf(applet);
        ta.notePiccEphemeral(uncompressed(idIc), (short) 0, (short) 65);
        ta.noteTerminalEphemeral(uncompressed(caKeyHash), (short) 0, (short) 65);
        byte[] at = doTag(0x83, chain.terminal.certificateHolderReference().encode());
        Mse.process(applet, (byte) 0x81, (byte) 0xA4, at, (short) 0, (short) at.length);
        GetChallenge.process(applet);
        byte[] challenge = (byte[]) field(TaContext.class, "challenge").get(ta);
        byte[] signature = Ecdsa.sign(concat(idIc, challenge, caKeyHash),
                chain.terminalPrivateScalar, new SecureRandom());
        ExternalAuthenticate.process(applet, signature, (short) 0, (short) signature.length);
    }

    /**
     * Current-date mechanism (BSI TR-03110-3 §2.5): the ICC current date is
     * advanced from a valid certificate's Effective Date, and an expired DV
     * certificate is rejected.
     */
    private static void currentDateMechanism() throws Exception {
        SecureRandom random = new SecureRandom();
        java.math.BigInteger cvcaScalar = P256.randomScalar(random);
        byte[] cvcaW = P256.encode(P256.scalarMult(cvcaScalar, P256.generator()));
        CvcPrincipal cvcaRef = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal dvRef = CvcPrincipal.of("UTDV000000000002");
        java.math.BigInteger dvScalar = P256.randomScalar(random);
        byte[] dvW = P256.encode(P256.scalarMult(dvScalar, P256.generator()));
        java.util.Map<String, byte[]> noAuth = new java.util.LinkedHashMap<String, byte[]>();

        CvCertificate valid = CvCertificateBuilder.build(0, cvcaRef, dvRef,
                Chat.Role.DV_DOMESTIC, new byte[] { (byte) 0x03 }, dvW, "250101", "300101",
                noAuth, cvcaScalar, random);
        EmrtdApplet applet = lds1Applet();
        personalizeLds1Ta(applet, cvcaW, cvcaRef.encode(), "240101");
        TaContext ta = taOf(applet);
        byte[] dst = doTag(0x83, valid.certificationAuthorityReference().encode());
        Mse.process(applet, (byte) 0x81, (byte) 0xB6, dst, (short) 0, (short) dst.length);
        PsoVerifyCertificate.process(applet, pso(valid), (short) 0, (short) pso(valid).length);
        Asserts.bytes(new byte[] { 2, 5, 0, 1, 0, 1 },
                (byte[]) field(TaContext.class, "currentDate").get(ta),
                "current date advanced to the DV Effective Date 250101");

        CvCertificate expired = CvCertificateBuilder.build(0, cvcaRef, dvRef,
                Chat.Role.DV_DOMESTIC, new byte[] { (byte) 0x03 }, dvW, "230101", "230201",
                noAuth, cvcaScalar, random);
        EmrtdApplet other = lds1Applet();
        personalizeLds1Ta(other, cvcaW, cvcaRef.encode(), "240101");
        byte[] dst2 = doTag(0x83, expired.certificationAuthorityReference().encode());
        byte[] pso2 = pso(expired);
        Asserts.sw((short) 0x6A80, () -> {
            Mse.process(other, (byte) 0x81, (byte) 0xB6, dst2, (short) 0, (short) dst2.length);
            PsoVerifyCertificate.process(other, pso2, (short) 0, (short) pso2.length);
        }, "an expired DV certificate (before the current date) -> 6A80");
    }

    /** Personalizes the LDS1 trust point (FF07) and current date (FF08). */
    private static void personalizeLds1Ta(EmrtdApplet applet, byte[] w, byte[] car,
                                          String currentDate) throws Exception {
        // The TA state is package-shared; reset the session before re-personalizing.
        taOf(applet).clearSession();
        ByteArrayOutputStream trustPoint = new ByteArrayOutputStream();
        trustPoint.write(w, 0, w.length);
        trustPoint.write(car.length);
        trustPoint.write(car, 0, car.length);

        ByteArrayOutputStream sequence = new ByteArrayOutputStream();
        writeDgi(sequence, EmrtdTags.DGI_BAC_SEED, new byte[16]);
        writeDgi(sequence, EmrtdTags.FID_DG1, new byte[] { 0x61, 0x03, 0x5F, 0x1F, 0x00 });
        writeDgi(sequence, EmrtdTags.DGI_TA_TRUST_POINT, trustPoint.toByteArray());
        if (currentDate != null) {
            byte[] date = new byte[6];
            for (int i = 0; i < 6; i++) {
                date[i] = (byte) (currentDate.charAt(i) - '0');
            }
            writeDgi(sequence, EmrtdTags.DGI_TA_CURRENT_DATE, date);
        }
        byte[] bytes = sequence.toByteArray();
        Field field = EmrtdApplet.class.getDeclaredField("perso");
        field.setAccessible(true);
        LdsPerso perso = (LdsPerso) field.get(applet);
        perso.apply(bytes, (short) 0, (short) bytes.length);
    }

    /** Personalizes the LDS2 trust point (FF07) with the given Travel authorization. */
    private static void setTravelTrustPoint(EmrtdApplet applet, TaChain.Chain chain, byte travel)
            throws Exception {
        taOf(applet).clearSession();
        byte[] w = chain.cvca.ecPublicKey();
        byte[] car = chain.cvca.certificateHolderReference().encode();
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.write(w, 0, w.length);
        value.write(car.length);
        value.write(car, 0, car.length);
        value.write(0x03); // ePassport CHAT
        value.write(travel);
        value.write(0x0F); // Visa
        value.write(0x0F); // Biometrics
        byte[] dgi = new byte[value.size() + 3];
        dgi[0] = (byte) 0xFF;
        dgi[1] = 0x07;
        dgi[2] = (byte) value.size();
        System.arraycopy(value.toByteArray(), 0, dgi, 3, value.size());

        Field field = EmrtdApplet.class.getDeclaredField("lds2Perso");
        field.setAccessible(true);
        Lds2Perso perso = (Lds2Perso) field.get(applet);
        perso.apply(dgi, (short) 0, (short) dgi.length);
    }

    private static EmrtdApplet travelApplet() throws Exception {
        Constructor<EmrtdApplet> ctor = EmrtdApplet.class.getDeclaredConstructor(
                byte.class, byte[].class, short.class);
        ctor.setAccessible(true);
        EmrtdApplet applet = ctor.newInstance(EmrtdInstallParameters.ROLE_LDS2_TRAVEL,
                EmrtdTags.DF_NAME_TRAVEL, (short) EmrtdTags.DF_NAME_TRAVEL.length);
        field(EmrtdApplet.class, "paceDone").setBoolean(applet, true);
        return applet;
    }

    private static void importChain(EmrtdApplet applet, TaChain.Chain chain) {
        for (byte[] encoded : chain.toSend()) {
            CvCertificate certificate = CvCertificateCodec.parse(encoded);
            byte[] dst = mseSetDst(certificate);
            byte[] pso = pso(certificate);
            Mse.process(applet, (byte) 0x81, (byte) 0xB6, dst, (short) 0, (short) dst.length);
            PsoVerifyCertificate.process(applet, pso, (short) 0, (short) pso.length);
        }
    }

    /** Writes the CVCA trust point DGI (FF07 = W(65) || refLen(1) || CAR). */
    private static void setTrustPoint(EmrtdApplet applet, TaChain.Chain chain) throws Exception {
        // The TA state is package-shared; reset the session before re-personalizing.
        taOf(applet).clearSession();
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

    private static TaContext taOf(EmrtdApplet applet) throws Exception {
        return (TaContext) field(EmrtdApplet.class, "ta").get(applet);
    }

    private static Field field(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field;
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

    private static byte[] uncompressed(byte[] x) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, x.length);
        return out;
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
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
