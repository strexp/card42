package card42.test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import javax.crypto.Cipher;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.cli.CliSupport;
import card42.host.common.codec.DerWriter;
import card42.host.common.crypto.Iso9797;
import card42.host.common.transport.Terminal;
import card42.host.common.util.Hex;
import card42.host.emrtd.access.Bac;
import card42.host.emrtd.access.ChipAuth;
import card42.host.emrtd.access.Iso7816Sm;
import card42.host.emrtd.aa.ActiveAuthentication;
import card42.host.emrtd.cli.Main;
import card42.host.emrtd.lds.AlgorithmIds;
import card42.host.emrtd.lds.CardAccess;
import card42.host.emrtd.lds.CardSecurity;
import card42.host.emrtd.lds.ChipAuthenticationInfo;
import card42.host.emrtd.lds.Dg15;
import card42.host.emrtd.lds.LdsReader;
import card42.host.emrtd.lds.SecurityInfo;
import card42.host.emrtd.transport.EmrtdTerminal;

/**
 * Negative and boundary tests for the host eMRTD modules that the positive
 * integration suite does not reach (WP6-1):
 *
 * <ul>
 *   <li>BAC failure paths - a wrong {@code M_IC} and a wrong recovered random
 *       (Doc 9303-11 §4.3, §9.7.3);</li>
 *   <li>secure-messaging response MAC and structure rejection
 *       (Doc 9303-11 §9.8.4);</li>
 *   <li>EF.CardAccess PACE selection fallbacks - DH generic mapping and an
 *       unmapped profile (BSI TR-03110-3 A.3);</li>
 *   <li>LDS1 READ BINARY 6CXX retry and the 6B00/6A82 end-of-EF branches
 *       (Doc 9303-10 §3.6.3);</li>
 *   <li>EF.CardSecurity outer {@code 77} strip (Doc 9303-10 §3.11.4);</li>
 *   <li>algorithm OID mapping including the ECDSA signature OIDs
 *       (Doc 9303-11 §9.2);</li>
 *   <li>RSA ISO/IEC 9796-2 Scheme 1 Active Authentication with a SHA-256
 *       trailer, and its tamper rejection (Doc 9303-11 §6.1.2.2);</li>
 *   <li>CLI exit codes that need no card (toolchain.md §7).</li>
 * </ul>
 */
final class EmrtdHostNegativeTest {

    private EmrtdHostNegativeTest() {
    }

    static void run() throws Exception {
        System.out.println("EmrtdHostNegative");
        bacFailures();
        secureMessagingFailures();
        cardAccessFallbacks();
        ldsReaderBranches();
        cardSecurityOuterTag();
        algorithmOids();
        hostChipAuthRejection();
        rsaActiveAuthentication();
        cliExitCodes();
    }

    /** BAC must reject a wrong M_IC and a wrong recovered random (§9.7.3). */
    private static void bacFailures() throws Exception {
        byte[] seed = Hex.parse("0F0E0D0C0B0A09080706050403020100");
        byte[] kmac = Bac.deriveKey(seed, 2);
        byte[] rndIcc = Hex.parse("1122334455667788");

        // M_IC mismatch: the card returns a random E_IC with a wrong 8-byte MAC.
        byte[] eic = Hex.parse("AABBCCDDEEFF00112233445566778899"
                + "0102030405060708090A0B0C0D0E0F10");
        ScriptedTerminal wrongMac = new ScriptedTerminal();
        wrongMac.add(0x9000, rndIcc);
        wrongMac.add(0x9000, concat(eic, Hex.parse("0000000000000000")));
        Asserts.rejects(() -> authenticate(wrongMac, seed), "BAC rejects a wrong M_IC");

        // Random mismatch: the M_IC is correct but E_IC does not carry RND.ICC.
        byte[] mic = mac(kmac, eic);
        ScriptedTerminal wrongRandom = new ScriptedTerminal();
        wrongRandom.add(0x9000, rndIcc);
        wrongRandom.add(0x9000, concat(eic, mic));
        Asserts.rejects(() -> authenticate(wrongRandom, seed), "BAC rejects a wrong recovered random");
    }

    private static void authenticate(ScriptedTerminal terminal, byte[] seed) {
        try {
            Bac.authenticate(new EmrtdTerminal(terminal), seed);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] mac(byte[] key16, byte[] data) {
        try {
            return Iso9797.mac(key16, data);
        } catch (java.security.GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /** The response MAC (DO8E) is mandatory and must verify (§9.8.4). */
    private static void secureMessagingFailures() {
        Iso7816Sm sm = new Iso7816Sm(Hex.parse("00112233445566778899AABBCCDDEEFF"),
                Hex.parse("0102030405060708090A0B0C0D0E0F10"), 0);
        short[] sw = new short[1];

        // A structurally complete response with a zeroed DO8E (DO99 = 9000).
        Asserts.rejects(() -> unwrap(sm, Hex.parse("990290008E080000000000000000"), sw),
                "secure messaging rejects a wrong response MAC");
        Asserts.rejects(() -> unwrap(sm, Hex.parse("99029000"), sw),
                "secure messaging rejects a response without DO8E");
    }

    private static void unwrap(Iso7816Sm sm, byte[] response, short[] sw) {
        try {
            sm.unwrapResponse(response, sw);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** PACE selection prefers ECDH-GM, falls back to DH-GM, else first (A.3). */
    private static void cardAccessFallbacks() {
        byte[] dhGm = DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_PACE_DH_GM_3DES),
                DerWriter.integer(2), DerWriter.integer(1));
        byte[] ecdhGm = DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_PACE_ECDH_GM_3DES),
                DerWriter.integer(2), DerWriter.integer(1));
        byte[] dhIm = DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_PACE_DH_IM),
                DerWriter.integer(2), DerWriter.integer(1));

        CardAccess onlyDh = CardAccess.parse(DerWriter.set(dhGm));
        Asserts.check(onlyDh.selectPace() != null && onlyDh.selectPace().isDhGenericMapping(),
                "PACE selects DH generic mapping when it is the only profile");

        CardAccess both = CardAccess.parse(DerWriter.set(dhGm, ecdhGm));
        Asserts.check(both.selectPace() != null && both.selectPace().isEcdhGenericMapping(),
                "PACE prefers ECDH over DH generic mapping");

        CardAccess unmapped = CardAccess.parse(DerWriter.set(dhIm));
        Asserts.check(unmapped.selectPace() != null
                        && SecurityInfo.ID_PACE_DH_IM.equals(unmapped.selectPace().oid),
                "PACE falls back to the first info for an unmapped profile");
    }

    /** LDS1 READ BINARY 6CXX retry and the 6B00/6A82 end-of-EF branches. */
    private static void ldsReaderBranches() throws Exception {
        // 6CXX: the card reports the exact length; the reader re-reads with it.
        ScriptedTerminal retry = new ScriptedTerminal();
        byte[] exact = Hex.parse("00112233445566778899AABBCCDDEEFF");
        retry.add(0x9000, new byte[0]);          // SELECT FILE
        retry.add(0x6C10, new byte[0]);          // READ BINARY wrong Le -> 6C 10
        retry.add(0x9000, exact);                // retry with Le = 0x10
        retry.add(0x9000, new byte[0]);          // next offset: EF end (0 bytes)
        Asserts.bytes(exact, LdsReader.read(new EmrtdTerminal(retry), 0x0101),
                "READ BINARY retries 6CXX with the exact length");
        Asserts.eq(0x10, retry.commands.get(2).getNe(),
                "READ BINARY 6CXX retry uses Le = SW2");

        // A short window must NOT be treated as EOF: under AES secure messaging
        // the card caps a window at 223 B although the reader requested 0xE7, so
        // the reader continues until the offset passes the EF end.
        ScriptedTerminal shortWindow = new ScriptedTerminal();
        byte[] first = new byte[100];
        byte[] second = new byte[50];
        for (int i = 0; i < first.length; i++) {
            first[i] = (byte) i;
        }
        for (int i = 0; i < second.length; i++) {
            second[i] = (byte) (i + 100);
        }
        shortWindow.add(0x9000, new byte[0]);    // SELECT FILE
        shortWindow.add(0x9000, first);          // short window (< CHUNK)
        shortWindow.add(0x9000, second);         // more data
        shortWindow.add(0x9000, new byte[0]);    // EF end
        byte[] joined = new byte[first.length + second.length];
        System.arraycopy(first, 0, joined, 0, first.length);
        System.arraycopy(second, 0, joined, first.length, second.length);
        Asserts.bytes(joined, LdsReader.read(new EmrtdTerminal(shortWindow), 0x0101),
                "a short window does not end the read");

        // 6B00: offset beyond the end of the EF ends the read.
        ScriptedTerminal endB = new ScriptedTerminal();
        byte[] full = new byte[LdsReader.CHUNK];
        for (int i = 0; i < full.length; i++) {
            full[i] = (byte) i;
        }
        endB.add(0x9000, new byte[0]);
        endB.add(0x9000, full);
        endB.add(0x6B00, new byte[0]);
        Asserts.bytes(full, LdsReader.read(new EmrtdTerminal(endB), 0x0101),
                "READ BINARY 6B00 ends the EF");

        // 6A82: EF not found while advancing ends the read the same way.
        ScriptedTerminal endA = new ScriptedTerminal();
        endA.add(0x9000, new byte[0]);
        endA.add(0x9000, full);
        endA.add(0x6A82, new byte[0]);
        Asserts.bytes(full, LdsReader.read(new EmrtdTerminal(endA), 0x0101),
                "READ BINARY 6A82 ends the EF");

        // Any other error propagates.
        ScriptedTerminal error = new ScriptedTerminal();
        error.add(0x9000, new byte[0]);
        error.add(0x6982, new byte[0]);
        Asserts.rejects(() -> read(error), "READ BINARY unexpected error is rejected");
    }

    private static void read(ScriptedTerminal terminal) {
        try {
            LdsReader.read(new EmrtdTerminal(terminal), 0x0101);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** EF.CardSecurity may be wrapped in an outer {@code 77} (Doc 9303-10 §3.11.4). */
    private static void cardSecurityOuterTag() {
        byte[] pace = DerWriter.sequence(DerWriter.oid(SecurityInfo.ID_PACE_ECDH_GM_3DES),
                DerWriter.integer(2), DerWriter.integer(1));
        byte[] set = DerWriter.set(pace);
        byte[] alg = DerWriter.sequence(DerWriter.oid("2.16.840.1.101.3.4.2.1"),
                DerWriter.nullValue());
        byte[] encap = DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.7.1"),
                DerWriter.context(0, DerWriter.octetString(set)));
        byte[] sid = DerWriter.sequence(DerWriter.sequence(DerWriter.oid("2.5.4.3")),
                DerWriter.integer(1));
        byte[] signerInfo = DerWriter.sequence(DerWriter.integer(1), sid, alg, alg,
                DerWriter.octetString(new byte[] { 1 }));
        byte[] signedData = DerWriter.sequence(DerWriter.integer(1), DerWriter.set(alg),
                encap, DerWriter.set(signerInfo));
        byte[] cms = DerWriter.sequence(DerWriter.oid("1.2.840.113549.1.7.2"),
                DerWriter.context(0, signedData));

        CardSecurity plain = CardSecurity.parse(cms);
        CardSecurity wrapped = CardSecurity.parse(DerWriter.tlv(0x77, cms));
        Asserts.eq(plain.securityInfos.size(), wrapped.securityInfos.size(),
                "outer 77 does not change the SecurityInfo count");
        Asserts.check(wrapped.securityInfos.size() == 1, "outer 77 SecurityInfo parsed");
    }

    /** The ECDSA signature OIDs map to the JDK names (Doc 9303-11 §9.2). */
    private static void algorithmOids() {
        Asserts.eq("SHA256withRSA", AlgorithmIds.signature("1.2.840.113549.1.1.11"),
                "RSA SHA-256 signature OID");
        Asserts.eq("SHA256withECDSA", AlgorithmIds.signature("1.2.840.10045.4.3.2"),
                "ECDSA SHA-256 signature OID");
        Asserts.eq("SHA384withECDSA", AlgorithmIds.signature("1.2.840.10045.4.3.3"),
                "ECDSA SHA-384 signature OID");
        Asserts.eq("SHA-256", AlgorithmIds.digest("2.16.840.1.101.3.4.2.1"),
                "SHA-256 digest OID");
        Asserts.eq("9.9.9", AlgorithmIds.signature("9.9.9"), "unknown signature OID passes through");
        Asserts.eq("9.9.8", AlgorithmIds.digest("9.9.8"), "unknown digest OID passes through");
    }

    /**
     * The host Chip Authentication supports only the ECDH + 3DES profile and
     * must reject the others before touching the transport (Doc 9303-11 §6.2.4.2).
     */
    private static void hostChipAuthRejection() {
        ChipAuthenticationInfo dh = caInfo(SecurityInfo.ID_CA_DH_3DES);
        ChipAuthenticationInfo aes = caInfo(SecurityInfo.ID_CA_ECDH_AES_128);
        Asserts.rejects(() -> hostChipAuth(dh), "host CA rejects a non-ECDH profile");
        Asserts.rejects(() -> hostChipAuth(aes), "host CA rejects a non-3DES profile");
    }

    private static ChipAuthenticationInfo caInfo(String oid) {
        byte[] ca = DerWriter.sequence(DerWriter.oid(oid), DerWriter.integer(2),
                DerWriter.integer(1));
        CardAccess access = CardAccess.parse(DerWriter.set(ca));
        return access.chipAuthenticationInfos().get(0);
    }

    private static void hostChipAuth(ChipAuthenticationInfo info) {
        try {
            ChipAuth.authenticate(null, new byte[65], info);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * RSA ISO/IEC 9796-2 Scheme 1 with the SHA-256 trailer option 2: the verifier
     * recovers the message and checks the embedded hash (Doc 9303-11 §6.1.2.2).
     */
    private static void rsaActiveAuthentication() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair pair = generator.generateKeyPair();
        Dg15 dg15 = Dg15.parse(tlv(0x6F, pair.getPublic().getEncoded()));
        Asserts.check(!dg15.ecdsa, "DG15 detects an RSA AA key");

        byte[] rndIfd = Hex.parse("0102030405060708");
        byte[] block = iso9796Block(pair, rndIfd);
        Asserts.check(ActiveAuthentication.verifySignature(dg15, rndIfd, block),
                "RSA ISO 9796-2 SHA-256 AA verifies");
        Asserts.check(!ActiveAuthentication.verifySignature(dg15,
                        Hex.parse("0102030405060709"), block),
                "RSA AA rejects a different RND.IFD");

        // A mismatched embedded hash (same trailer) is rejected.
        byte[] tampered = block.clone();
        tampered[100] ^= 0x40;
        Asserts.check(!ActiveAuthentication.verifySignature(dg15, rndIfd, tampered),
                "RSA AA rejects a tampered signature");

        // An unknown trailer option is not an ISO 9796-2 Scheme 1 signature.
        Asserts.check(!ActiveAuthentication.verifySignature(dg15, rndIfd,
                        new byte[128]),
                "RSA AA rejects a non-9796-2 block");
    }

    /**
     * Builds an ISO/IEC 9796-2 Scheme 1 signature over {@code M1 || RND.IFD}
     * with a SHA-256 trailer (option 2: hash id 0x34 then 0xCC), signed with the
     * raw RSA private-key operation so the test is independent of the card key.
     *
     * <p>The card encoding is {@code 0x6A || M1 || H(M) || trailer}
     * (card/emrtd/crypto/AaCrypto.java), where the leading 0x6A is the
     * message-recovery separator the verifier scans for.
     */
    private static byte[] iso9796Block(KeyPair pair, byte[] rndIfd) throws Exception {
        byte[] block = new byte[128];
        int digestLength = 32;
        int m1Length = block.length - digestLength - 2 - 1; // 0x6A + H + trailer
        byte[] m1 = new byte[m1Length];
        for (int i = 0; i < m1Length; i++) {
            m1[i] = (byte) (i + 1);
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(m1);
        digest.update(rndIfd);
        byte[] hash = digest.digest();

        block[0] = 0x6A;
        System.arraycopy(m1, 0, block, 1, m1Length);
        System.arraycopy(hash, 0, block, 1 + m1Length, digestLength);
        block[block.length - 2] = 0x34; // SHA-256 hash id (option 2)
        block[block.length - 1] = (byte) 0xCC;

        Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
        rsa.init(Cipher.ENCRYPT_MODE, pair.getPrivate());
        return rsa.doFinal(block);
    }

    /** Exit codes that the CLI resolves before it opens a card connection. */
    private static void cliExitCodes() {
        Asserts.eq(CliSupport.EXIT_OK, Main.run(new String[] { "version" }),
                "CLI version exits 0");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(new String[0]),
                "CLI without arguments exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(new String[] { "bogus" }),
                "CLI unknown command exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE, Main.run(new String[] { "terminal", "emrtd" }),
                "CLI missing subcommand exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE,
                Main.run(new String[] { "terminal", "emrtd", "nope" }),
                "CLI unknown subcommand exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE,
                Main.run(new String[] { "terminal", "emrtd", "lds2", "-app=bogus" }),
                "CLI unknown LDS2 app exits 2");
        Asserts.eq(CliSupport.EXIT_USAGE,
                Main.run(new String[] { "terminal", "emrtd", "apdu" }),
                "CLI apdu without -apdu exits 2");
    }

    private static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        card42.host.common.codec.TlvWriter.writeTlv(out, tag, value);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int off = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, off, part.length);
            off += part.length;
        }
        return out;
    }

    /**
     * A {@link Terminal} backed by a scripted list of R-APDUs.  It overrides
     * {@code transmit} so the LdsReader 6CXX branch is reached without the T=0
     * retry of the production terminal.
     */
    private static final class ScriptedTerminal extends Terminal {

        private final List<CommandAPDU> commands = new ArrayList<CommandAPDU>();
        private final Deque<ResponseAPDU> responses = new ArrayDeque<ResponseAPDU>();

        ScriptedTerminal() {
            super((CardChannel) null);
        }

        void add(int sw, byte[] data) {
            byte[] out = new byte[data.length + 2];
            System.arraycopy(data, 0, out, 0, data.length);
            out[data.length] = (byte) (sw >> 8);
            out[data.length + 1] = (byte) sw;
            responses.add(new ResponseAPDU(out));
        }

        @Override
        public ResponseAPDU transmit(CommandAPDU command) {
            commands.add(command);
            ResponseAPDU response = responses.poll();
            if (response == null) {
                throw new IllegalStateException("unexpected command "
                        + Hex.format(command.getBytes()));
            }
            return response;
        }
    }
}
