package card42.host.common.cli;

import java.io.PrintStream;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Small command registry shared by the EMV and eMRTD CLIs.  It keeps the
 * top-level command names, their usage text and their entry points in one
 * place instead of a switch duplicated between dispatch and help.
 */
public final class CommandRegistry {

    /** One top-level command. */
    public interface Command {
        int run(String[] args) throws Exception;

        void usage(PrintStream out);
    }

    private final Map<String, Command> commands = new LinkedHashMap<String, Command>();

    public CommandRegistry register(String name, Command command) {
        if (commands.put(name, command) != null) {
            throw new IllegalStateException("duplicate command: " + name);
        }
        return this;
    }

    public Command get(String name) {
        return commands.get(name);
    }

    public boolean contains(String name) {
        return commands.containsKey(name);
    }

    /** Runs a registered command; returns null when the name is unknown. */
    public Integer dispatch(String name, String[] args) throws Exception {
        Command command = commands.get(name);
        return command == null ? null : command.run(args);
    }


}
