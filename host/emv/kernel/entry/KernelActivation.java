package card42.host.emv.kernel.entry;

/**
 * The data Entry Point passes to the selected kernel at activation
 * (EMV Contactless Book B v2.12 §3.4): the selected ADF Name and AID, the
 * Kernel ID, the PPSE FCI the Combination was selected from, and the
 * Pre-Processing Indicators computed in Start A.
 *
 * <p>The kernel activation parameters are consumed by the Entry Point state
 * machine ({@code ContactlessKernel}); the media-neutral {@code TransactionFlow}
 * only needs the ADF Name / FCI already placed on the result.
 */
public final class KernelActivation {

    /** The Directory Entry's ADF Name used for SELECT. */
    public final String adfName;
    /**
     * The ADF Name actually sent in SELECT (ADF Name with the Extended
     * Selection appended when applicable, EMV Contactless Book B v2.12
     * §3.3.3.3); it is the ADF Name reported in the Final Outcome
     * (Book B §3.5.1.5).
     */
    public final String selectedAdfName;
    /** The reader Combination AID the ADF Name matched. */
    public final String aid;
    /** The Kernel ID of the selected Combination. */
    public final int kernelId;
    /** The PPSE FCI the Candidate List was read from (or the SPI response FCI). */
    public final byte[] ppseFci;
    /** The FCI returned by SELECT (ADF Name) (Book B §3.4.1.3). */
    public final byte[] adfFci;
    /** The SW1 SW2 returned by SELECT (ADF Name) (Book B §3.4.1.3). */
    public final int adfSw;
    /** The Pre-Processing Indicators (Book A Table 5-3), Start A or Start B. */
    public final PreProcessingIndicators indicators;
    /** The Entry Point Start that produced this activation (Outcome.START_A/B/C/D). */
    public final int start;

    public KernelActivation(String adfName, String selectedAdfName, String aid, int kernelId,
            byte[] ppseFci, byte[] adfFci, int adfSw, PreProcessingIndicators indicators, int start) {
        this.adfName = adfName;
        this.selectedAdfName = selectedAdfName;
        this.aid = aid;
        this.kernelId = kernelId;
        this.ppseFci = ppseFci;
        this.adfFci = adfFci;
        this.adfSw = adfSw;
        this.indicators = indicators;
        this.start = start;
    }

    /**
     * The Kernel Identifier-Terminal (tag '96', 8 bytes) built from the selected
     * Kernel ID (EMV Contactless Book B v2.12 §3.4.1.4): bytes 1-3 carry the
     * Kernel ID, byte 4 the Kernel 8 support bits (this reader implements no
     * Kernel 8), bytes 5-8 are RFU.
     */
    public byte[] kernelIdentifierTerminal() {
        return new byte[] { (byte) (kernelId >> 16), (byte) (kernelId >> 8),
                (byte) kernelId, 0x00, 0x00, 0x00, 0x00, 0x00 };
    }
}
