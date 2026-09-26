package card42.host.emv.report;

/**
 * ReceiptPrinter SPI: presents a {@link Receipt} to the cardholder (print,
 * screen, ...).  The actual presentation is out of scope of this project and
 * lives in a separate UI project; {@link #NONE} is the no-op default.
 */
public interface ReceiptPrinter {

    /** Presents the receipt. */
    void print(Receipt receipt);

    /** The no-op printer. */
    ReceiptPrinter NONE = receipt -> {
    };
}
