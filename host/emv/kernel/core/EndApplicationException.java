package card42.host.emv.kernel.core;

/**
 * The Entry Point <em>End Application</em> Outcome (EMV Contactless Book B
 * v2.12 §3.3.2.7 / §3.3.3.5): no supported Combination remains, so the kernel
 * ends the application and the reader presents the End Application UI request.
 *
 * <p>Full Outcome Processing (Book B §3.5) is out of scope for this project
 * (docs/specs/emv/contactless.md §1.2), so the kernel surfaces the outcome as this
 * checked exception carrying the UI Request message identifier instead of
 * driving the reader UI itself.
 */
public class EndApplicationException extends KernelException {

    /** UI Request message identifier '1C' ("Insert, Swipe or Try Another Card"). */
    public static final int INSERT_SWIPE_OR_TRY_ANOTHER_CARD = 0x1C;
    /** UI Request message identifier '18' ("Try Another Interface"). */
    public static final int TRY_ANOTHER_INTERFACE = 0x18;

    private static final long serialVersionUID = 1L;

    private final int messageIdentifier;

    public EndApplicationException(String message) {
        this(message, INSERT_SWIPE_OR_TRY_ANOTHER_CARD);
    }

    public EndApplicationException(String message, int messageIdentifier) {
        super(message);
        this.messageIdentifier = messageIdentifier;
    }

    /** The UI Request message identifier of the End Application Outcome. */
    public int messageIdentifier() {
        return messageIdentifier;
    }
}
