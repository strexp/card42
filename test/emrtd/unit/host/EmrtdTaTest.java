package card42.test;

import card42.host.emrtd.lds.security.*;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import card42.host.common.codec.DerWriter;
import card42.host.common.crypto.Ecdsa;
import card42.host.common.crypto.P256;
import card42.host.common.crypto.RsaPss;
import card42.host.emrtd.lds.security.SecurityInfo;
import card42.host.emrtd.lds.security.TerminalAuthenticationInfo;
import card42.host.emrtd.ta.Chat;
import card42.host.emrtd.ta.CvCertificate;
import card42.host.emrtd.ta.CvCertificateBuilder;
import card42.host.emrtd.ta.CvCertificateCodec;
import card42.host.emrtd.ta.CvChainVerifier;
import card42.host.emrtd.ta.CvcPrincipal;
import card42.host.emrtd.tools.TaChain;
import card42.host.emrtd.ta.TerminalAuth;

/**
 * Pure-JVM tests for the Terminal Authentication host stack: the self-contained
 * ECDSA (cross-checked against the JDK), CV certificate codec, chain
 * verification, effective authorization, and the
 * {@code ID_IC||rIC||Comp(PKDH,IFD)} signature input.
 */
final class EmrtdTaTest {

    private EmrtdTaTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdTa");
        ecdsaSelfTest();
        ecdsaJceCrossCheck();
        certificateRoundTrip();
        chainVerification();
        rsaCertificate();
        rsaIssuerChain();
        effectiveAuthorization();
        terminalAuthInput();
        terminalAuthenticationInfo();
    }

    private static void ecdsaSelfTest() {
        SecureRandom random = new SecureRandom();
        BigInteger d = P256.randomScalar(random);
        byte[] w = P256.encode(P256.scalarMult(d, P256.generator()));
        byte[] message = "terminal authentication".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] signature = Ecdsa.sign(message, d, random);
        Asserts.eq(64, signature.length, "ECDSA plain signature is 64 bytes");
        Asserts.check(Ecdsa.verify(message, w, signature), "ECDSA sign/verify round-trip");
        byte[] tamperedMessage = message.clone();
        tamperedMessage[0] ^= 0x01;
        Asserts.check(!Ecdsa.verify(tamperedMessage, w, signature),
                "ECDSA rejects a tampered message");
        byte[] tamperedSignature = signature.clone();
        tamperedSignature[0] ^= 0x01;
        Asserts.check(!Ecdsa.verify(message, w, tamperedSignature),
                "ECDSA rejects a tampered signature");
    }

    /** Cross-checks the self-contained ECDSA against the JDK's SHA256withECDSA. */
    private static void ecdsaJceCrossCheck() throws Exception {
        SecureRandom random = new SecureRandom();
        BigInteger d = P256.randomScalar(random);
        byte[] w = P256.encode(P256.scalarMult(d, P256.generator()));
        byte[] message = "cross check".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] plain = Ecdsa.sign(message, d, random);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(jcePublicKey(w));
        verifier.update(message);
        Asserts.check(verifier.verify(plainToDer(plain)),
                "JDK SHA256withECDSA verifies our plain signature");
    }

    private static void certificateRoundTrip() {
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        CvCertificate parsed = CvCertificateCodec.parse(chain.terminal.encoded());
        Asserts.eq(chain.terminal.certificateHolderReference().name(),
                parsed.certificateHolderReference().name(), "CHR round-trips");
        Asserts.eq(CvCertificate.OID_TA_ECDSA_SHA_256, parsed.publicKeyOid(), "public-key OID");
        Asserts.check(parsed.isEc() && parsed.ecPublicKey().length == 65,
                "EC public point is 65 bytes");
        Asserts.check(Chat.Role.IS == parsed.chat().role,
                "IS role from the discretionary byte");
        Asserts.eq("250101", parsed.effectiveDate(), "effective date round-trips");
        Asserts.eq("300101", parsed.expirationDate(), "expiration date round-trips");
        Asserts.bytes(chain.terminalPublicKeyW, parsed.ecPublicKey(),
                "terminal public key round-trips");
        Asserts.check(Arrays.equals(chain.terminal.body(), parsed.body()),
                "body TLV is byte-identical");
        Asserts.check(Ecdsa.verify(parsed.body(), chain.dv.ecPublicKey(), parsed.signature()),
                "IS certificate is signed by the DV key");
    }

    private static void chainVerification() {
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        List<CvCertificate> parsed = new ArrayList<CvCertificate>();
        for (byte[] encoded : chain.toSend()) {
            parsed.add(CvCertificateCodec.parse(encoded));
        }
        CvCertificate terminal = CvChainVerifier.verify(parsed, chain.cvca.ecPublicKey());
        Asserts.eq(chain.terminal.certificateHolderReference().name(),
                terminal.certificateHolderReference().name(),
                "verified chain ends at the terminal certificate");

        // A corrupted DV certificate must fail.
        byte[] tampered = chain.dv.encoded().clone();
        tampered[tampered.length - 1] ^= 0x01;
        List<CvCertificate> tamperedChain = new ArrayList<CvCertificate>();
        tamperedChain.add(CvCertificateCodec.parse(tampered));
        tamperedChain.add(CvCertificateCodec.parse(chain.terminal.encoded()));
        Asserts.rejects(() -> CvChainVerifier.verify(tamperedChain, chain.cvca.ecPublicKey()),
                "a corrupted certificate fails chain verification");

        // A wrong trust anchor must fail.
        byte[] otherAnchor = P256.encode(P256.scalarMult(P256.randomScalar(new SecureRandom()),
                P256.generator()));
        Asserts.rejects(() -> CvChainVerifier.verify(parsed, otherAnchor),
                "a wrong trust anchor fails chain verification");
    }

    /** The TAv2 RSA-PSS-SHA-256 certificate profile (BSI TR-03110-3 C.1.2.2). */
    private static void rsaCertificate() throws Exception {
        SecureRandom random = new SecureRandom();
        BigInteger cvca = P256.randomScalar(random);
        BigInteger dv = P256.randomScalar(random);
        byte[] cvcaW = P256.encode(P256.scalarMult(cvca, P256.generator()));
        byte[] dvW = P256.encode(P256.scalarMult(dv, P256.generator()));
        CvcPrincipal cvcaRef = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal dvRef = CvcPrincipal.of("UTDV000000000002");
        CvcPrincipal isRef = CvcPrincipal.of("UTIS000000000003");
        Map<String, byte[]> noAuth = new java.util.LinkedHashMap<String, byte[]>();
        java.security.KeyPair rsa = rsaKeyPair();
        byte[] mod = RsaPss.unsigned(
                ((java.security.interfaces.RSAPublicKey) rsa.getPublic()).getModulus());
        byte[] exp = RsaPss.unsigned(
                ((java.security.interfaces.RSAPublicKey) rsa.getPublic()).getPublicExponent());

        CvCertificate dvCert = CvCertificateBuilder.build(0, cvcaRef, dvRef,
                Chat.Role.DV_DOMESTIC, new byte[] { (byte) 0x03 }, dvW, "250101", "300101",
                noAuth, cvca, random);
        // RSA subject key, signed by the EC DV (an RSA cert carried over ECDSA).
        byte[] body = CvCertificateCodec.encodeBodyRsa(0, dvRef,
                CvCertificate.OID_TA_RSA_PSS_SHA_256, mod, exp, isRef, Chat.Role.IS,
                new byte[] { (byte) 0x03 }, "250101", "300101", noAuth);
        CvCertificate terminal = CvCertificateCodec.parse(
                CvCertificateCodec.encode(body, Ecdsa.sign(body, dv, random)));

        CvCertificate parsed = CvCertificateCodec.parse(terminal.encoded());
        Asserts.check(parsed.isRsa(), "RSA terminal certificate parses as RSA");
        Asserts.eq(CvCertificate.OID_TA_RSA_PSS_SHA_256, parsed.publicKeyOid(),
                "RSA terminal certificate carries the RSA-PSS OID");
        Asserts.bytes(mod, parsed.rsaModulus(), "RSA modulus round-trips");
        Asserts.bytes(exp, parsed.rsaExponent(), "RSA exponent round-trips");

        List<CvCertificate> chain = new ArrayList<CvCertificate>();
        chain.add(dvCert);
        chain.add(parsed);
        CvCertificate verified = CvChainVerifier.verify(chain, cvcaW);
        Asserts.eq(isRef.name(), verified.certificateHolderReference().name(),
                "RSA terminal certificate chain verifies against the EC trust anchor");

        byte[] message = "terminal authentication".getBytes(
                java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] signature = RsaPss.sign(message, rsa.getPrivate());
        Asserts.check(RsaPss.verify(message, RsaPss.publicKey(mod, exp), signature),
                "RSA-PSS sign/verify round-trip");
        Asserts.check(!RsaPss.verify(message, RsaPss.publicKey(mod, exp), tamper(signature)),
                "RSA-PSS rejects a tampered signature");
    }

    /** An RSA issuer key signing an EC terminal certificate with RSA-PSS. */
    private static void rsaIssuerChain() throws Exception {
        SecureRandom random = new SecureRandom();
        BigInteger cvca = P256.randomScalar(random);
        BigInteger is = P256.randomScalar(random);
        byte[] cvcaW = P256.encode(P256.scalarMult(cvca, P256.generator()));
        byte[] isW = P256.encode(P256.scalarMult(is, P256.generator()));
        CvcPrincipal cvcaRef = CvcPrincipal.of("UTCVCA0000000001");
        CvcPrincipal dvRef = CvcPrincipal.of("UTDV000000000002");
        CvcPrincipal isRef = CvcPrincipal.of("UTIS000000000003");
        Map<String, byte[]> noAuth = new java.util.LinkedHashMap<String, byte[]>();

        java.security.KeyPair dvRsa = rsaKeyPair();
        byte[] mod = RsaPss.unsigned(
                ((java.security.interfaces.RSAPublicKey) dvRsa.getPublic()).getModulus());
        byte[] exp = RsaPss.unsigned(
                ((java.security.interfaces.RSAPublicKey) dvRsa.getPublic()).getPublicExponent());
        // The DV certificate has an RSA key and is signed by the EC CVCA.
        byte[] dvBody = CvCertificateCodec.encodeBodyRsa(0, cvcaRef,
                CvCertificate.OID_TA_RSA_PSS_SHA_256, mod, exp, dvRef, Chat.Role.DV_DOMESTIC,
                new byte[] { (byte) 0x03 }, "250101", "300101", noAuth);
        CvCertificate dvCert = CvCertificateCodec.parse(
                CvCertificateCodec.encode(dvBody, Ecdsa.sign(dvBody, cvca, random)));
        // The terminal certificate has an EC key and is signed by the RSA DV (RSA-PSS).
        byte[] termBody = CvCertificateCodec.encodeBody(0, dvRef,
                CvCertificate.OID_TA_ECDSA_SHA_256, isW, isRef, Chat.Role.IS,
                new byte[] { (byte) 0x03 }, "250101", "300101", noAuth);
        CvCertificate terminal = CvCertificateCodec.parse(
                CvCertificateCodec.encode(termBody, RsaPss.sign(termBody, dvRsa.getPrivate())));

        List<CvCertificate> chain = new ArrayList<CvCertificate>();
        chain.add(dvCert);
        chain.add(terminal);
        CvCertificate verified = CvChainVerifier.verify(chain, cvcaW);
        Asserts.eq(isRef.name(), verified.certificateHolderReference().name(),
                "an RSA-signed certificate verifies against an RSA DV key");
    }

    private static java.security.KeyPair rsaKeyPair() throws Exception {
        java.security.KeyPairGenerator generator =
                java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static byte[] tamper(byte[] value) {
        byte[] out = value.clone();
        out[out.length / 2] ^= 0x01;
        return out;
    }

    private static void effectiveAuthorization() {
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        Map<String, byte[]> effective = CvChainVerifier.effectiveAuthorization(chain.fullChain());
        Asserts.bytes(new byte[] { (byte) 0x0F }, effective.get(CvCertificate.OID_LDS2_TRAVEL),
                "Travel authorization is ANDed across the chain");
        Asserts.check(CvChainVerifier.granted(effective.get(CvCertificate.OID_LDS2_TRAVEL), 1),
                "effective authorization grants the append bit");
    }

    private static void terminalAuthInput() {
        byte[] identifier = new byte[32];
        Arrays.fill(identifier, (byte) 0x11);
        byte[] challenge = new byte[8];
        Arrays.fill(challenge, (byte) 0x22);
        byte[] keyHash = new byte[32];
        Arrays.fill(keyHash, (byte) 0x33);
        byte[] input = TerminalAuth.signatureInput(identifier, challenge, keyHash);
        Asserts.eq(72, input.length, "signature input is ID_IC || rIC || Comp = 72 bytes");
        Asserts.bytes(identifier, Arrays.copyOfRange(input, 0, 32), "input starts with ID_IC");
        Asserts.bytes(challenge, Arrays.copyOfRange(input, 32, 40), "then rIC");
        Asserts.bytes(keyHash, Arrays.copyOfRange(input, 40, 72), "then Comp(PKDH,IFD)");

        TaChain.Chain chain = TaChain.create(new SecureRandom());
        Asserts.bytes(P256.x(P256.decode(chain.terminalPublicKeyW)),
                TerminalAuth.chipAuthenticationKeyHash(chain.terminalPublicKeyW),
                "Comp(PKDH,IFD) is the x-coordinate");
    }

    private static void terminalAuthenticationInfo() {
        byte[] sequence = DerWriter.sequence(
                DerWriter.oid(SecurityInfo.ID_TA), DerWriter.integer(2));
        List<SecurityInfo> infos = SecurityInfo.parseList(DerWriter.set(sequence));
        Asserts.check(infos.size() == 1 && infos.get(0) instanceof TerminalAuthenticationInfo,
                "EF.CardAccess parses a TerminalAuthenticationInfo");
        Asserts.eq(2, ((TerminalAuthenticationInfo) infos.get(0)).version,
                "TerminalAuthenticationInfo version is 2");
    }

    private static java.security.PublicKey jcePublicKey(byte[] w) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(w, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(w, 33, 65));
        return KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
    }

    private static byte[] plainToDer(byte[] plain) {
        return DerWriter.sequence(derInteger(plain, 0), derInteger(plain, 32));
    }

    private static byte[] derInteger(byte[] value, int off) {
        int start = off;
        int len = 32;
        while (len > 1 && value[start] == 0) {
            start++;
            len--;
        }
        byte[] v = Arrays.copyOfRange(value, start, start + len);
        if ((v[0] & 0x80) != 0) {
            byte[] padded = new byte[v.length + 1];
            System.arraycopy(v, 0, padded, 1, v.length);
            v = padded;
        }
        return DerWriter.tlv(0x02, v);
    }
}
