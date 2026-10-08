package card42.test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import card42.host.common.codec.DerWriter;
import card42.host.common.codec.TlvWriter;
import card42.host.common.util.Hex;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.ChipAuthenticationInfo;
import card42.host.emrtd.lds.ChipAuthenticationPublicKeyInfo;
import card42.host.emrtd.lds.Dg;
import card42.host.emrtd.lds.LdsSecurityObject;
import card42.host.emrtd.lds.PaceInfo;
import card42.host.emrtd.lds.SecurityInfo;
import card42.host.emrtd.lds.Sod;
import card42.host.emrtd.lds.UnknownSecurityInfo;
import card42.host.emrtd.pa.CscaKeyStore;
import card42.host.emrtd.pa.PassiveAuthentication;
import card42.host.emrtd.perso.SodBuilder;
import card42.host.emrtd.perso.EmrtdPersoExporter;

/**
 * Pure-JVM tests for host EF.CardAccess / SecurityInfo parsing, the
 * generic DG3-DG16 parser and Passive Authentication tamper rejection.
 */
final class EmrtdCardAccessTest {

    private EmrtdCardAccessTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdCardAccess");
        securityInfoParsing();
        cardSecurityParsing();
        genericDataGroups();
        passiveAuthenticationTamper();
        passiveAuthenticationSignerSelection();
    }

    /** EF.CardSecurity is a CMS SignedData over the SecurityInfo set (H7.2). */
    private static void cardSecurityParsing() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair chip = generator.generateKeyPair();
        byte[] pace = DerWriter.sequence(DerWriter.oid("0.4.0.127.0.7.2.2.4.2.2"),
                DerWriter.integer(2), DerWriter.integer(12));
        byte[] caKey = DerWriter.sequence(DerWriter.oid("0.4.0.127.0.7.2.2.1.2"),
                chip.getPublic().getEncoded(), DerWriter.integer(1));
        byte[] set = DerWriter.set(pace, caKey);

        byte[] alg = DerWriter.sequence(DerWriter.oid("2.16.840.1.101.3.4.2.1"),
                DerWriter.nullValue());
        byte[] encap = DerWriter.sequence(DerWriter.oid("0.4.0.127.0.7.3.2.1"),
                DerWriter.context(0, DerWriter.octetString(set)));
        byte[] cert = EmrtdPersoExporter.loadCertificate("perso/emrtd/dsc.crt").getEncoded();
        byte[] sid = DerWriter.sequence(DerWriter.sequence(DerWriter.oid("2.5.4.3")),
                DerWriter.integer(1));
        byte[] signerInfo = DerWriter.sequence(DerWriter.integer(1), sid, alg, alg,
                DerWriter.octetString(new byte[] { 1 }));
        byte[] signedData = DerWriter.sequence(DerWriter.integer(1), DerWriter.set(alg),
                encap, DerWriter.context(0, cert), DerWriter.set(signerInfo));
        byte[] cms = DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.7.2"),
                DerWriter.context(0, signedData));

        card42.host.emrtd.lds.CardSecurity security =
                card42.host.emrtd.lds.CardSecurity.parse(cms);
        Asserts.eq(2, security.securityInfos.size(), "CardSecurity SecurityInfo count");
        Asserts.eq(1, security.publicKeyInfos().size(), "CardSecurity CA public key");
        Asserts.check(security.publicKeyInfos().get(0).toPublicKey() != null,
                "CardSecurity CA public key rebuilt");
        Asserts.check(security.signerCertificate() != null, "CardSecurity signer certificate");
    }

    private static void securityInfoParsing() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair chip = generator.generateKeyPair();

        byte[] pace = DerWriter.sequence(
                DerWriter.oid("0.4.0.127.0.7.2.2.4.2.2"),
                DerWriter.integer(2),
                DerWriter.integer(12));
        byte[] caInfo = DerWriter.sequence(
                DerWriter.oid("0.4.0.127.0.7.2.2.3.2.1"),
                DerWriter.integer(1),
                DerWriter.integer(1));
        byte[] caKey = DerWriter.sequence(
                DerWriter.oid("0.4.0.127.0.7.2.2.1.2"),
                chip.getPublic().getEncoded(),
                DerWriter.integer(1));
        byte[] aa = DerWriter.sequence(
                DerWriter.oid("2.23.136.1.1.5"),
                DerWriter.integer(1),
                DerWriter.oid("1.2.840.113549.1.1.11"));
        byte[] set = DerWriter.set(pace, caInfo, caKey, aa);

        CardAccess access = CardAccess.parse(set);
        Asserts.eq(4, access.securityInfos.size(), "CardAccess SecurityInfo count");
        Asserts.eq(1, access.paceInfos().size(), "one PACE info");
        Asserts.check(access.selectPace() != null
                && access.selectPace().isEcdhGenericMapping(), "PACE ECDH GM selected");
        Asserts.eq(12, access.selectPace().parameterId, "PACE parameter id");

        Asserts.eq(1, access.chipAuthenticationInfos().size(), "one CA info");
        ChipAuthenticationInfo info = access.chipAuthenticationInfos().get(0);
        // ChipAuthenticationInfo.version MUST be 1 (ICAO Doc 9303-11 §9.2.5);
        // PACE uses version 2 instead (§9.2.2), so the two are asserted
        // separately.
        Asserts.eq(1, info.version, "CA version is 1 (Doc 9303-11 §9.2.5)");
        Asserts.eq("ECDH", info.keyAgreement(), "CA key agreement");
        Asserts.eq("DESede", info.cipherAlgorithm(), "CA cipher");

        SecurityInfo keyInfo = access.securityInfos.get(2);
        Asserts.check(keyInfo instanceof ChipAuthenticationPublicKeyInfo,
                "CA public key info parsed");
        Asserts.check(((ChipAuthenticationPublicKeyInfo) keyInfo).isEcdh(),
                "CA public key is ECDH");
        Asserts.check(((ChipAuthenticationPublicKeyInfo) keyInfo).toPublicKey() != null,
                "CA public key rebuilt");

        // An unrecognised SecurityInfo OID is preserved (not dropped) and typed
        // as UnknownSecurityInfo, so the base contract holds (L3).
        byte[] unknown = DerWriter.sequence(DerWriter.oid("1.2.3.4.5"),
                DerWriter.integer(1));
        CardAccess withUnknown = CardAccess.parse(DerWriter.set(unknown));
        Asserts.eq(1, withUnknown.securityInfos.size(), "unknown SecurityInfo preserved");
        Asserts.check(withUnknown.securityInfos.get(0) instanceof UnknownSecurityInfo,
                "unknown SecurityInfo typed");
        Asserts.eq("unrecognised protocol", withUnknown.securityInfos.get(0).describe(),
                "unknown SecurityInfo described");
    }

    private static void genericDataGroups() throws Exception {
        byte[] inner = tlv(0x5F0E, "ERIKSSON".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] dg11 = Dg.wrap(11, inner);
        Dg parsed = Dg.parse(dg11);
        Asserts.eq(11, parsed.number, "DG11 number");
        Asserts.eq(0x6B, parsed.outerTag, "DG11 outer tag");
        Asserts.eq("ERIKSSON", new String(parsed.value(0x5F0E),
                java.nio.charset.StandardCharsets.US_ASCII), "DG11 inner value");
        Asserts.eq(0x6C, card42.host.emrtd.lds.LdsFileUtil.dgTag(12), "DG12 tag");
        Asserts.eq(12, card42.host.emrtd.lds.LdsFileUtil.dgForTag(0x6C), "DG tag -> number");

        // DG14 = 6E { SET OF SecurityInfo } (Doc 9303-10 §4.7.14): the generic
        // parser sees the outer 6E tag, and the SecurityInfos set it wraps is
        // the same one EF.CardSecurity signs, so the host SecurityInfo layer
        // recovers the chip's static CA public key.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair ca = generator.generateKeyPair();
        byte[] securityInfos = card42.host.emrtd.perso.CardSecurityBuilder.securityInfos(
                ca.getPublic().getEncoded(), 1, null);
        Dg dg14 = Dg.parse(Dg.wrap(14, securityInfos));
        Asserts.eq(14, dg14.number, "DG14 number");
        Asserts.eq(0x6E, dg14.outerTag, "DG14 outer tag");
        Asserts.eq(0x010E, card42.host.emrtd.lds.LdsFileUtil.FID_DG14, "DG14 FID");
        java.util.List<SecurityInfo> infos = SecurityInfo.parseList(securityInfos);
        Asserts.eq(1, infos.size(), "DG14 SecurityInfo count");
        Asserts.check(infos.get(0) instanceof ChipAuthenticationPublicKeyInfo,
                "DG14 CA public key info");
    }

    private static void passiveAuthenticationTamper() throws Exception {
        byte[] dg1 = tlv(0x61, tlv(0x5F1F, (EmrtdPersoExporter.LINE1 + EmrtdPersoExporter.LINE2)
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        byte[] dg15 = Hex.parse("6F00");
        java.util.Map<Integer, byte[]> hashes = new java.util.LinkedHashMap<Integer, byte[]>();
        hashes.put(1, java.security.MessageDigest.getInstance("SHA-256").digest(dg1));
        hashes.put(15, java.security.MessageDigest.getInstance("SHA-256").digest(dg15));

        byte[] sod = SodBuilder.build(hashes,
                EmrtdPersoExporter.loadPrivateKey("perso/emrtd/dsc.key"),
                EmrtdPersoExporter.loadCertificate("perso/emrtd/dsc.crt"));
        CscaKeyStore trust = CscaKeyStore.fromFiles(new java.io.File("perso/emrtd/csca.crt"));
        LdsSecurityObject securityObject = PassiveAuthentication.verify(Sod.parse(sod), trust);
        Asserts.check(PassiveAuthentication.verifyDataGroup(securityObject, 1, dg1),
                "untampered DG1 matches the SOD");
        Asserts.check(!PassiveAuthentication.verifyDataGroup(securityObject, 1, tamper(dg1)),
                "tampered DG1 is rejected");
        Asserts.check(!PassiveAuthentication.verifyDataGroup(securityObject, 1, dg15),
                "DG1/DG15 hash substitution is rejected");

        CscaKeyStore wrongTrust = CscaKeyStore.fromFiles(
                new java.io.File("perso/emrtd/dsc.crt"));
        try {
            PassiveAuthentication.verify(Sod.parse(sod), wrongTrust);
            Asserts.check(false, "SOD under a wrong CSCA is rejected");
        } catch (Exception e) {
            Asserts.check(true, "SOD under a wrong CSCA is rejected");
        }
    }

    /**
     * Passive Authentication selects the DSC by the SignerInfo sid and enforces
     * the mandatory contentType signed attribute (RFC 5652 §5.3/§5.4).
     */
    private static void passiveAuthenticationSignerSelection() throws Exception {
        byte[] dg1 = tlv(0x61, tlv(0x5F1F, (EmrtdPersoExporter.LINE1 + EmrtdPersoExporter.LINE2)
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        java.util.Map<Integer, byte[]> hashes = new java.util.LinkedHashMap<Integer, byte[]>();
        hashes.put(1, MessageDigest.getInstance("SHA-256").digest(dg1));
        PrivateKey key = EmrtdPersoExporter.loadPrivateKey("perso/emrtd/dsc.key");
        X509Certificate cert = EmrtdPersoExporter.loadCertificate("perso/emrtd/dsc.crt");
        byte[] eContent = Sod.parse(SodBuilder.build(hashes, key, cert)).cms.eContent;
        CscaKeyStore trust = CscaKeyStore.fromFiles(new java.io.File("perso/emrtd/csca.crt"));

        byte[] goodSid = DerWriter.sequence(cert.getIssuerX500Principal().getEncoded(),
                DerWriter.integer(cert.getSerialNumber()));
        String type = "2.23.136.1.1.1";

        // Correct sid and contentType: accepted.
        Asserts.noThrow(() -> {
            try {
                PassiveAuthentication.verify(
                        Sod.parse(cms(type, type, goodSid, eContent, key, cert)), trust);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, "SOD with matching sid and contentType accepted");

        // The contentType signed attribute must equal the eContentType (§5.3).
        Asserts.rejects(() -> {
            try {
                PassiveAuthentication.verify(Sod.parse(cms(type, "1.2.840.113549.1.7.1",
                        goodSid, eContent, key, cert)), trust);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, "SOD contentType attribute mismatch rejected");

        // The sid must name a certificate actually carried in the SignedData (§5.4).
        byte[] wrongSid = DerWriter.sequence(cert.getIssuerX500Principal().getEncoded(),
                DerWriter.integer(cert.getSerialNumber().add(java.math.BigInteger.ONE)));
        Asserts.rejects(() -> {
            try {
                PassiveAuthentication.verify(
                        Sod.parse(cms(type, type, wrongSid, eContent, key, cert)), trust);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, "SOD signer sid without a matching certificate rejected");
    }

    /**
     * Builds a CMS SignedData with an explicit eContentType and contentType
     * signed attribute, signed by the DSC key (test fixture).
     */
    private static byte[] cms(String eContentType, String contentTypeAttr, byte[] sid,
                              byte[] eContent, PrivateKey key, X509Certificate cert)
            throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(eContent);
        byte[] signedAttrsContent = DerWriter.concat(
                DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.9.3"),
                        DerWriter.set(DerWriter.oid(contentTypeAttr))),
                DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.9.4"),
                        DerWriter.set(DerWriter.octetString(digest))));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(DerWriter.set(signedAttrsContent));
        byte[] signature = signer.sign();

        byte[] alg = DerWriter.sequence(DerWriter.oid("2.16.840.1.101.3.4.2.1"),
                DerWriter.nullValue());
        byte[] sigAlg = DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.1.11"),
                DerWriter.nullValue());
        byte[] signerInfo = DerWriter.sequence(DerWriter.integer(1), sid, alg,
                DerWriter.context(0, signedAttrsContent), sigAlg,
                DerWriter.octetString(signature));
        byte[] signedData = DerWriter.sequence(DerWriter.integer(1), DerWriter.set(alg),
                DerWriter.sequence(DerWriter.oid(eContentType),
                        DerWriter.context(0, DerWriter.octetString(eContent))),
                DerWriter.context(0, cert.getEncoded()), DerWriter.set(signerInfo));
        return DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.7.2"),
                DerWriter.context(0, signedData));
    }

    private static byte[] tamper(byte[] dg) {
        byte[] copy = dg.clone();
        copy[copy.length - 1] ^= 0x01;
        return copy;
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }
}
