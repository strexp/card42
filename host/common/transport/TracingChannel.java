package card42.host.common.transport;

import java.io.PrintStream;
import java.nio.ByteBuffer;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import card42.host.common.util.Hex;

/**
 * A {@link CardChannel} wrapper that logs every command/response pair, used by
 * the CLI {@code terminal pay -trace} and {@code terminal apdu -trace} options.
 *
 * <p>It prints {@code > C-APDU} and {@code < R-APDU SW=xxxx} lines to the given
 * stream (stderr in the CLI, so a {@code -json} report on stdout stays clean)
 * and otherwise delegates unchanged.
 */
public final class TracingChannel extends CardChannel {

    private final CardChannel delegate;
    private final PrintStream out;

    public TracingChannel(CardChannel delegate, PrintStream out) {
        this.delegate = delegate;
        this.out = out;
    }

    @Override
    public Card getCard() {
        return delegate.getCard();
    }

    @Override
    public int getChannelNumber() {
        return delegate.getChannelNumber();
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) throws CardException {
        out.println("> " + Hex.format(command.getBytes()));
        ResponseAPDU response = delegate.transmit(command);
        out.println("< " + Hex.format(response.getBytes())
                + String.format(" SW=%04X", response.getSW()));
        return response;
    }

    @Override
    public int transmit(ByteBuffer command, ByteBuffer response) throws CardException {
        // Trace this overload too, so a caller typed as CardChannel sees the same
        // "every exchange is logged" contract as the CommandAPDU overload.
        ByteBuffer commandView = command.duplicate();
        byte[] commandBytes = new byte[commandView.remaining()];
        commandView.get(commandBytes);
        out.println("> " + Hex.format(commandBytes));

        int responseStart = response.position();
        int length = delegate.transmit(command, response);

        ByteBuffer responseView = response.duplicate();
        responseView.position(responseStart);
        byte[] responseBytes = new byte[Math.min(length, responseView.remaining())];
        responseView.get(responseBytes);
        if (responseBytes.length >= 2) {
            int sw = ((responseBytes[responseBytes.length - 2] & 0xFF) << 8)
                    | (responseBytes[responseBytes.length - 1] & 0xFF);
            out.println("< " + Hex.format(responseBytes) + String.format(" SW=%04X", sw));
        } else {
            out.println("< " + Hex.format(responseBytes));
        }
        return length;
    }

    @Override
    public void close() throws CardException {
        delegate.close();
    }
}
