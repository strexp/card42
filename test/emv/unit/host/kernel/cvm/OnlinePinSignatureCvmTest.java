package card42.test;

import card42.host.emv.kernel.data.Cvm;
import card42.host.emv.crypto.AcCrypto;
import card42.host.emv.kernel.analysis.CvmList;
import card42.host.emv.kernel.analysis.CvmPerformer;
import card42.host.emv.kernel.core.OnlinePinProvider;
import card42.host.emv.kernel.core.SignatureProvider;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.emv.kernel.cvm.CombinedPinSignatureCvm;
import card42.host.emv.kernel.cvm.CompositeCvmPerformer;
import card42.host.emv.kernel.cvm.OnlinePinCvm;
import card42.host.emv.kernel.cvm.SignatureCvm;
import card42.host.emv.kernel.data.TerminalConfig;
import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.kernel.data.Tvr;
import card42.host.common.util.Hex;

/**
 * Pure-JVM tests for the online PIN, signature and combined CVM performers
 * and for their routing through {@link CvmList}
 * (EMV v4.4 Book 3 §10.5, Book 4 §6.3.4.4/Table 2/Table 43).
 */
final class OnlinePinSignatureCvmTest {

    private OnlinePinSignatureCvmTest() {
    }

    static void run() {
        System.out.println("OnlinePinSignatureCvm");

        // ISO 9564-1 format 0: PIN "1234" over PAN 1234567890123456
        // (check digit dropped, rightmost 12 digits) = 04 12 34 FF.. xor
        // 00 00 45 67 89 01 23 45.
        Asserts.bytes(Hex.parse("0412719876FEDCBA"),
                AcCrypto.iso9564Format0("1234", Hex.parse("1234567890123456")),
                "ISO 9564-1 format 0 PIN block");

        // Online PIN: the performer captures and encrypts, stores the block and
        // sets 'Online PIN entered' with an 'unknown' result.
        TransactionRequest data = contact();
        TransactionResult.Mutable result = withPan("1234567890123456");
        final byte[][] encrypted = new byte[1][];
        OnlinePinProvider provider = new OnlinePinProvider() {
            @Override
            public String pin() {
                return "1234";
            }

            @Override
            public byte[] encryptPinBlock(byte[] pinBlock) {
                encrypted[0] = pinBlock;
                return Hex.parse("0011223344556677");
            }
        };
        OnlinePinCvm online = new OnlinePinCvm(provider, data, result);
        Asserts.check(online.supports(Cvm.CVM_ONLINE_PIN), "online PIN supported");
        Asserts.check(!online.supports(Cvm.CVM_SIGNATURE), "online PIN not signature");
        Asserts.eq(Cvm.RESULT_UNKNOWN, online.perform(Cvm.CVM_ONLINE_PIN, 0),
                "online PIN result is unknown");
        Asserts.bytes(Hex.parse("0412719876FEDCBA"), encrypted[0],
                "performer builds the format 0 block");
        Asserts.bytes(Hex.parse("0011223344556677"), result.onlinePinBlock(),
                "encrypted block exposed on the result");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.ONLINE_PIN_ENTERED),
                "online PIN sets 'Online PIN entered'");

        // A bypassed PIN entry fails with 'PIN not entered'.
        data = contact();
        result = withPan("1234567890123456");
        online = new OnlinePinCvm(pinProvider(null, Hex.parse("0011223344556677")),
                data, result);
        Asserts.eq(Cvm.RESULT_FAILED, online.perform(Cvm.CVM_ONLINE_PIN, 0),
                "bypassed online PIN fails");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.PIN_NOT_ENTERED),
                "bypassed online PIN sets 'PIN not entered'");

        // Without a PAN the format 0 block cannot be built.
        data = contact();
        result = new TransactionResult.Mutable().tvr(Tvr.blank());
        online = new OnlinePinCvm(pinProvider("1234", Hex.parse("0011223344556677")),
                data, result);
        Asserts.eq(Cvm.RESULT_FAILED, online.perform(Cvm.CVM_ONLINE_PIN, 0),
                "online PIN without PAN fails");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.PIN_PAD_NOT_PRESENT),
                "online PIN without PAN sets PIN pad not present");

        // Without a PIN encryption key the CVM fails.
        data = contact();
        result = withPan("1234567890123456");
        online = new OnlinePinCvm(pinProvider("1234", null), data, result);
        Asserts.eq(Cvm.RESULT_FAILED, online.perform(Cvm.CVM_ONLINE_PIN, 0),
                "online PIN without a key fails");
        Asserts.check(Tvr.isSet(result.tvr(), 2, Tvr.PIN_PAD_NOT_PRESENT),
                "online PIN without a key sets PIN pad not present");

        // Signature: a captured signature reports 'unknown'; a refusal fails.
        result = new TransactionResult.Mutable();
        SignatureCvm signature = new SignatureCvm(signatureProvider(Hex.parse("AABB")),
                result);
        Asserts.check(signature.supports(Cvm.CVM_SIGNATURE), "signature supported");
        Asserts.eq(Cvm.RESULT_UNKNOWN, signature.perform(Cvm.CVM_SIGNATURE, 0),
                "signature result is unknown");
        Asserts.bytes(Hex.parse("AABB"), result.signature(), "captured signature exposed");
        Asserts.eq(Cvm.RESULT_FAILED,
                new SignatureCvm(signatureProvider(null), new TransactionResult.Mutable())
                        .perform(Cvm.CVM_SIGNATURE, 0),
                "refused signature fails");

        // Combined '03': the PIN runs first and the signature only on success.
        SignatureCvm signatureOk = new SignatureCvm(signatureProvider(Hex.parse("AABB")),
                new TransactionResult.Mutable());
        CvmPerformer pinOk = pinStub(Cvm.CVM_PLAINTEXT_PIN_ICC,
                Cvm.RESULT_SUCCESSFUL);
        CombinedPinSignatureCvm combined = new CombinedPinSignatureCvm(pinOk, signatureOk);
        Asserts.check(combined.supports(Cvm.CVM_PLAINTEXT_PIN_SIGNATURE),
                "combined plaintext PIN + signature supported");
        Asserts.check(!combined.supports(Cvm.CVM_ENCIPHERED_PIN_SIGNATURE),
                "combined enciphered not supported by a plaintext-only PIN stub");
        Asserts.eq(Cvm.RESULT_UNKNOWN,
                combined.perform(Cvm.CVM_PLAINTEXT_PIN_SIGNATURE, 0),
                "combined success reports unknown (signature unverifiable)");
        Asserts.eq(Cvm.RESULT_FAILED,
                new CombinedPinSignatureCvm(pinStub(Cvm.CVM_PLAINTEXT_PIN_ICC,
                        Cvm.RESULT_FAILED), signatureOk)
                        .perform(Cvm.CVM_PLAINTEXT_PIN_SIGNATURE, 0),
                "combined fails when the PIN fails");
        Asserts.eq(Cvm.RESULT_FAILED,
                new CombinedPinSignatureCvm(pinOk,
                        new SignatureCvm(signatureProvider(null), new TransactionResult.Mutable()))
                        .perform(Cvm.CVM_PLAINTEXT_PIN_SIGNATURE, 0),
                "combined fails when the signature is refused");

        // CvmList routes online PIN and the combined CVM to the performer even
        // when the capability booleans are clear.
        data = contact();
        result = withPan("1234567890123456");
        CvmPerformer composite = new CompositeCvmPerformer(
                new OnlinePinCvm(pinProvider("1234", Hex.parse("0011223344556677")),
                        data, result),
                new SignatureCvm(signatureProvider(Hex.parse("AABB")), result));
        byte[] tvr = result.tvr();
        CvmList.Result r = CvmList.process(Hex.parse("00000000000000000200"), 500,
                0, false, false, 0, true, 0x00, composite, tvr);
        Asserts.eq(Cvm.CVM_ONLINE_PIN, r.code, "CvmList selects online PIN via performer");
        Asserts.eq(Cvm.RESULT_UNKNOWN, r.result, "online PIN via CvmList is unknown");
        Asserts.check(result.onlinePinBlock() != null,
                "online PIN block exposed via CvmList");

        data = contact();
        result = withPan("1234567890123456");
        composite = new CompositeCvmPerformer(
                new CombinedPinSignatureCvm(
                        pinStub(Cvm.CVM_PLAINTEXT_PIN_ICC, Cvm.RESULT_SUCCESSFUL),
                        new SignatureCvm(signatureProvider(Hex.parse("AABB")), result)));
        tvr = result.tvr();
        r = CvmList.process(Hex.parse("00000000000000000300"), 500,
                0, false, false, 0, true, 0x00, composite, tvr);
        Asserts.eq(Cvm.CVM_PLAINTEXT_PIN_SIGNATURE, r.code,
                "CvmList selects the combined CVM via performer");
        Asserts.eq(Cvm.RESULT_UNKNOWN, r.result, "combined CVM via CvmList is unknown");
    }

    /** A contact transaction request with the default contact configuration. */
    private static TransactionRequest contact() {
        return new TransactionRequest(TerminalConfig.forContact().build());
    }

    /** A mutable result carrying record 1 with a PAN (tag 5A) and a blank TVR. */
    private static TransactionResult.Mutable withPan(String panHex) {
        TransactionResult.Mutable result = new TransactionResult.Mutable();
        result.putRecord(1, concat(Hex.parse("700A5A08"), Hex.parse(panHex)));
        result.tvr(Tvr.blank()).tsi(new byte[2]);
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static OnlinePinProvider pinProvider(final String pin, final byte[] encrypted) {
        return new OnlinePinProvider() {
            @Override
            public String pin() {
                return pin;
            }

            @Override
            public byte[] encryptPinBlock(byte[] pinBlock) {
                return encrypted;
            }
        };
    }

    private static SignatureProvider signatureProvider(final byte[] captured) {
        return new SignatureProvider() {
            @Override
            public byte[] capture() {
                return captured;
            }
        };
    }

    private static CvmPerformer pinStub(final int method, final int result) {
        return new CvmPerformer() {
            @Override
            public boolean supports(int m) {
                return m == method;
            }

            @Override
            public int perform(int m, int condition) {
                return result;
            }
        };
    }
}
