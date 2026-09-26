package card42.host.common.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Small command-line option parser for the host CLI.
 *
 * <p>An option is {@code -name=value} or {@code -name value}; a flag is a bare
 * {@code -name}.  The parser is told up front which names are value options and
 * which are flags, so it can reject an unknown option instead of silently
 * ignoring it.  {@code -h}/{@code --help} are always flags.  Non-option
 * arguments are kept as positionals.
 *
 * <p>A repeated value option keeps every value ({@link #all}); {@link #get}
 * returns the last one.
 */
public final class Args {

    private final Map<String, String> values = new LinkedHashMap<>();
    private final Map<String, List<String>> lists = new LinkedHashMap<>();
    private final Set<String> flags = new LinkedHashSet<>();
    private final List<String> positional = new ArrayList<>();

    /**
     * Parses {@code argv}.
     *
     * @param valueOptions names that take a value ({@code -name value})
     * @param flagOptions  names that are bare flags ({@code -name})
     * @throws IllegalArgumentException on an unknown option, a missing value or
     *                                  a value given to a flag
     */
    public Args(String[] argv, String[] valueOptions, String[] flagOptions) {
        Set<String> valueNames = new HashSet<>(Arrays.asList(valueOptions));
        Set<String> flagNames = new HashSet<>(Arrays.asList(flagOptions));
        flagNames.add("h");
        flagNames.add("help");

        for (int i = 0; i < argv.length; i++) {
            String arg = argv[i];
            if (arg.isEmpty() || arg.charAt(0) != '-' || arg.equals("-")) {
                positional.add(arg);
                continue;
            }
            String body = arg.startsWith("--") ? arg.substring(2) : arg.substring(1);
            String name;
            String value = null;
            int eq = body.indexOf('=');
            if (eq >= 0) {
                name = body.substring(0, eq);
                value = body.substring(eq + 1);
            } else {
                name = body;
            }
            if (flagNames.contains(name)) {
                if (value != null) {
                    throw new IllegalArgumentException("Option -" + name + " takes no value");
                }
                flags.add(name);
                continue;
            }
            if (!valueNames.contains(name)) {
                throw new IllegalArgumentException("Unknown option: -" + name);
            }
            if (value == null) {
                if (i + 1 >= argv.length) {
                    throw new IllegalArgumentException("Option -" + name + " needs a value");
                }
                value = argv[++i];
            }
            values.put(name, value);
            lists.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
    }

    /** True when the option or flag was present. */
    public boolean has(String name) {
        return flags.contains(name) || values.containsKey(name);
    }

    /** The last value of an option, or {@code defaultValue} when absent. */
    public String get(String name, String defaultValue) {
        String value = values.get(name);
        return value == null ? defaultValue : value;
    }

    /** The value of a required option; throws when it is absent. */
    public String require(String name) {
        String value = values.get(name);
        if (value == null) {
            throw new IllegalArgumentException("Missing required option: -" + name);
        }
        return value;
    }

    /** Every value of a repeated option, in order (empty when absent). */
    public List<String> all(String name) {
        List<String> list = lists.get(name);
        return list == null ? List.of() : list;
    }

    /** The non-option arguments, in order. */
    public List<String> positional() {
        return positional;
    }

    /** True when {@code -h} or {@code --help} was given. */
    public boolean help() {
        return flags.contains("h") || flags.contains("help");
    }
}
