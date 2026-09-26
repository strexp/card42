package card42.emrtd;

/* The PACE key-seed sink (personalization DGI FF04).
 *
 * {@code Lds2Perso} depends on this narrow interface rather than the concrete
 * {@link Pace} so the LDS2 personalization path stays compilable in the
 * pure-JVM unit build, which links only a subset of the card classes.
 *
 * @author card42
 */

public interface PaceSeedSink {

    /** Stores the 20-byte PACE key seed SHA-1(MRZ_info). */
    void setSeed(byte[] src, short off, short len);
}
