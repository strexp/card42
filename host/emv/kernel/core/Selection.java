package card42.host.emv.kernel.core;

import card42.host.emv.kernel.data.TransactionRequest;
import card42.host.emv.lib.Terminal;

/**
 * The application selection step of a terminal kernel: how the kernel finds and
 * selects the ADF to transact with.  The contact kernel selects the PSE (or an
 * ADF directly), the contactless kernel selects the PPSE and runs the Entry
 * Point Combination Selection (EMV Contactless Book B v2.12 §3.3.2).
 */
public interface Selection {

    /**
     * Selects an application and returns its ADF Name in hex.  On success the
     * implementation must set {@code result.aidHex} and {@code result.fci}.
     *
     * @throws Exception when no supported application can be selected
     */
    String select(Terminal terminal, TransactionRequest data, TransactionResult.Mutable result)
            throws Exception;

    /**
     * Removes the currently selected application from the candidate list and
     * selects the next supported one (EMV v4.4 Book 4 §6.3.1: a GET PROCESSING
     * OPTIONS '6985' makes the terminal return to application selection).
     *
     * <p>Every {@code Selection} must implement this: a kernel with a single
     * candidate returns null, one with a list returns the next ADF Name.
     *
     * @return the next ADF Name in hex, or null when no candidate remains
     */
    String reselect(Terminal terminal, TransactionRequest data, TransactionResult.Mutable result)
            throws Exception;
}
