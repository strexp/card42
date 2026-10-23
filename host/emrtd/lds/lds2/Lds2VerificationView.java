package card42.host.emrtd.lds.lds2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Rendering-facing view of one LDS2 record verification result.  It lives in
 * the LDS2 model package so the report does not depend on {@code pa}; the
 * verifier converts its richer result to this shape at the CLI boundary.
 */
public final class Lds2VerificationView {

    public final String label;
    public final boolean signatureValid;
    public final CertificateView certificate;
    public final List<String> problems;

    public Lds2VerificationView(String label, boolean signatureValid,
                                CertificateView certificate, List<String> problems) {
        this.label = label;
        this.signatureValid = signatureValid;
        this.certificate = certificate;
        this.problems = Collections.unmodifiableList(
                new ArrayList<String>(problems == null ? Collections.<String>emptyList() : problems));
    }

    public boolean valid() {
        return signatureValid && certificate != null && certificate.valid();
    }

    public boolean validWithoutTrust() {
        return signatureValid && certificate != null && certificate.profileValid;
    }

    /** Certificate profile/trust fields needed by the report. */
    public static final class CertificateView {
        public final String subject;
        public final String country;
        public final boolean profileValid;
        public final boolean trusted;

        public CertificateView(String subject, String country,
                               boolean profileValid, boolean trusted) {
            this.subject = subject;
            this.country = country;
            this.profileValid = profileValid;
            this.trusted = trusted;
        }

        public boolean valid() {
            return profileValid && trusted;
        }
    }
}
