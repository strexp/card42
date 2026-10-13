package card42.emv;

/* The narrow surface PersoHandler drives on the applet it personalizes
 * (docs/specs/emv/personalization.md §1).
 *
 * It replaces PersoHandler's former dependency on the concrete EMVAppletBase so
 * the reassembly logic no longer knows the applet's protocol state, FCI, command
 * dispatch or role resolution.  EMVAppletBase implements it, so no wrapper
 * object (and no extra heap) is introduced.
 *
 * @author card42
 */

public interface PersoTarget {

    /** Builds the role-dependent data on the first block if it has not run yet. */
    void initIfNeeded();

    /** The lifecycle state; personalization only proceeds in PERSONALISATION. */
    byte lifecycle();

    /** Clears the per-instance completion markers of a personalization attempt. */
    void resetPersoState();

    /** Applies one DGI of the sequence (EMV CPS v2.0 Annex A). */
    void applyPersoDgi(short dgi, byte[] buf, short off, short len);

    /** True once every DGI required by the applet has been received. */
    boolean persoCheckComplete();

    /** Marks the instance as personalized (lifecycle -> READY). */
    void persoComplete();
}
