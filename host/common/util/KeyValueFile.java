package card42.host.common.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A tiny flat {@code key = value} text-file reader shared by the host CLI
 * profiles (SDA key profile, CA key ring, terminal configuration).
 *
 * <p>The format is deliberately minimal: one {@code key = value} per line,
 * {@code #} starts a comment, blank lines are ignored and a later key wins over
 * an earlier one.  Keys and values are trimmed; values may contain any
 * character except {@code #}.
 */
public final class KeyValueFile {

    private KeyValueFile() {
    }

    /** Reads the file into an ordered key/value map. */
    public static Map<String, String> read(String path) throws IOException {
        Map<String, String> props = new LinkedHashMap<>();
        for (String raw : Files.readAllLines(Path.of(path))) {
            String line = raw;
            int hash = line.indexOf('#');
            if (hash >= 0) {
                line = line.substring(0, hash);
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            int eq = line.indexOf('=');
            if (eq < 0) {
                throw new IOException("profile " + path + ": missing '=' in: " + raw);
            }
            props.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
        }
        return props;
    }
}
