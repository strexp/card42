package card42.host.emv.app.issuer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import card42.host.common.codec.Json;
import card42.host.emv.kernel.core.Authorization;
import card42.host.emv.kernel.core.Issuer;
import card42.host.emv.kernel.core.TransactionResult;
import card42.host.common.util.Hex;

/**
 * External host process issuer for {@code terminal pay} (docs/specs/common/toolchain.md
 * §7.1, decision D): one JSON request line on stdin, one JSON response line on
 * stdout.  Request fields: {@code arqc}, {@code atc}, {@code tvr}, {@code aid};
 * response fields: {@code arc}, {@code auth} (optional) and {@code scripts}
 * (optional array of hex templates).
 */
public final class SubprocessIssuer implements Issuer {

    private final String command;

    public SubprocessIssuer(String command) {
        this.command = command;
    }

    @Override
    public Authorization authorize(byte[] arqc, int atc, TransactionResult result) {
        try {
            String request = "{\"arqc\":" + Json.quote(Hex.format(arqc))
                    + ",\"atc\":" + atc
                    + ",\"tvr\":" + Json.quote(Hex.format(result.tvr()))
                    + ",\"aid\":" + Json.quote(result.aidHex() == null ? "" : result.aidHex())
                    + "}";
            ProcessBuilder builder = new ProcessBuilder(command.trim().split("\\s+"));
            builder.redirectError(ProcessBuilder.Redirect.INHERIT);
            Process process = builder.start();
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    process.getOutputStream(), StandardCharsets.UTF_8))) {
                writer.write(request);
                writer.newLine();
            }
            String line;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    process.getInputStream(), StandardCharsets.UTF_8))) {
                line = reader.readLine();
            }
            process.waitFor();
            if (line == null || line.isBlank()) {
                throw new IllegalStateException("-issuer-cmd returned no response");
            }
            Map<String, Object> response = Json.parseObject(line);
            byte[] arc = Hex.parse(Json.string(response, "arc") == null
                    ? "3035" : Json.string(response, "arc"));
            byte[] auth = Json.string(response, "auth") == null
                    ? null : Hex.parse(Json.string(response, "auth"));
            List<String> scripts = Json.strings(response, "scripts");
            byte[][] templates = new byte[scripts.size()][];
            for (int i = 0; i < scripts.size(); i++) {
                templates[i] = Hex.parse(scripts.get(i));
            }
            return new Authorization(arc, auth, templates.length == 0 ? null : templates);
        } catch (Exception e) {
            throw new RuntimeException("-issuer-cmd failed: " + e.getMessage(), e);
        }
    }
}
