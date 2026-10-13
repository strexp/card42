package card42.host.emrtd.cli.command;

import java.security.SecureRandom;

import card42.host.common.cli.Args;
import card42.host.common.cli.CliSupport;
import card42.host.common.util.Bytes;
import card42.host.common.util.Hex;
import card42.host.emrtd.ta.TaChain;

/**
 * {@code terminal emrtd ta-export}: writes a demo Terminal Authentication CV
 * certificate chain (CVCA trust anchor, DV, IS), the concatenated chain to send
 * and the terminal private key, for use with {@code read -ta}.
 */
final class EmrtdTaExportCommand {

    private EmrtdTaExportCommand() {
    }

    static int run(String[] args) throws Exception {
        Args parsed = new Args(args, new String[] { "dir" }, new String[0]);
        java.nio.file.Path dir = java.nio.file.Paths.get(parsed.get("dir", "."));
        java.nio.file.Files.createDirectories(dir);
        TaChain.Chain chain = TaChain.create(new SecureRandom());
        java.nio.file.Files.write(dir.resolve("cvca.der"), chain.cvca.encoded());
        java.nio.file.Files.write(dir.resolve("dv.der"), chain.dv.encoded());
        java.nio.file.Files.write(dir.resolve("is.der"), chain.terminal.encoded());
        java.nio.file.Files.write(dir.resolve("chain.der"),
                Bytes.concat(chain.dv.encoded(), chain.terminal.encoded()));
        byte[] key = new byte[32];
        byte[] raw = chain.terminalPrivateScalar.toByteArray();
        System.arraycopy(raw, Math.max(0, raw.length - 32), key,
                Math.max(0, 32 - raw.length), Math.min(32, raw.length));
        java.nio.file.Files.write(dir.resolve("terminal-key.hex"),
                Hex.format(key).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        System.out.println("wrote cvca.der, dv.der, is.der, chain.der, terminal-key.hex to " + dir);
        return CliSupport.EXIT_OK;
    }
}
