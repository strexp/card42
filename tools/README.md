# tools

This directory holds the external inputs the build, personalization and test
workflows rely on: **reference documents** (the standards the implementation is
written against), the **toolchain** (Java Card converter and off-card
verifier) and the **simulator**.  It is git-ignored and is not part of any
deliverable; every item below has to be obtained separately and placed here
before `make` can run.

> Third-party reference *implementations* (source trees or jars of other
> projects that implement the same standards) may also be kept here for local
> study, but they are not part of this project, are not described here and must
> not be referenced from the design documents or from source comments.

## 1. Reference documents

The implementation cites these documents by name and clause (for example
`EMV v4.4 Book 3 §5.4`, `EMV CPS v2.0 §4.3.4.6`, `Doc 9303-10 §5.1`).  Markdown
and/or PDF copies are expected under this directory; only the markdown text is
grepped during development.

| Document | Version | Used for | Where to obtain |
|----------|---------|----------|-----------------|
| EMV Book 1–4 | **v4.4 (2022-10)** — baseline | Contact ICC/terminal interface, security & key management, application specification, other interfaces | EMVCo specification library (free download after accepting the licence) |
| EMV CPS | **v2.0 (2021-08, with AES)** — baseline | Card personalization DGI/TLV model, SCP02/SCP03 | EMVCo specification library |
| EMV Contactless Book A/B | **v2.12** — baseline | Entry Point architecture, PPSE/combination selection, SPI | EMVCo specification library |
| EMV Contactless Book C-8 | **v1.2** — conceptual only | Kernel flow structure reference; its ECC/Book E parts are out of scope | EMVCo specification library |
| EMV Book 1–4 | v4.3 / v4.1 | Historical comparison only | EMVCo archive / older mirrors |
| EMV CPS | v1.1 | Historical comparison only (pre-AES) | EMVCo archive |
| ICAO Doc 9303 | Parts 3, 9, 10, 11, 12 | eMRTD LDS1/LDS2, BAC, secure messaging, PA/AA, PACE | ICAO e-publications (free) |
| BSI TR-03110 | Parts 1–4, v2.2 | PACE, Chip Authentication, EAC profiles and KDFs | BSI publications (free) |
| GlobalPlatform Card API | v1.7.1 (contains 1.5/1.6/1.7) and v1.8 | `org.globalplatform` API jar + converter export files | GlobalPlatform specifications library (account required) |

Notes:

- The **baseline** column is what the current design follows.  v4.1/v4.3 and
  CPS v1.1 are kept only so older behaviour can be compared.
- The GlobalPlatform Card API v1.7.1 archive bundles the `1.5/`, `1.6/` and
  `1.7/` variants.  This project uses **1.6**, matching the `org.globalplatform`
  package version of the simulator; see
  [`docs/specs/common/toolchain.md`](../docs/specs/common/toolchain.md) §1/§8.

## 2. Toolchain

| Tool | Version | Used for | Where to obtain |
|------|---------|----------|-----------------|
| Oracle Java Card Development Kit **Tools** | v26.0 | `javac`-side converter (`converter.sh`) and off-card verifier (`verifyexp.sh` / `verifycap.sh`) that build and verify the CAPs | Oracle Java Card downloads (Oracle account) |
| JDK | 21 or 25 (full JDK, must contain `bin/javac` and `bin/jar`) | Compiles applet classes (Java Card classic, `--release 8`) and the host jars | Any OpenJDK distribution |
| GlobalPlatformPro | git 26.06.04+ (must include nextgen) | Loads CAPs and creates/personalizes instances on both the simulator and a real card | GlobalPlatformPro releases (GitHub); this project expects it at `/usr/share/java/globalplatformpro/gp.jar` |

The build auto-detects the Java Card Tools directory.  The simulator transport
of GlobalPlatformPro (`--ng --simulator`) is upstream **experimental** and is
used **only** against the simulator; real cards use classic PC/SC.  See
[`docs/specs/common/toolchain.md`](../docs/specs/common/toolchain.md) §1/§4/§5.

## 3. Simulator

| Tool | Version | Used for | Where to obtain |
|------|---------|----------|-----------------|
| Oracle Java Card Development Kit **Simulator** (jcsl) | v26.0 | Runs the CAPs off-card for integration tests; reports Java Card 3.2 / GP 2.3 / SCP03 | Oracle Java Card downloads (Oracle account) |

The simulator is a 32-bit runtime with its own OpenSSL libraries.  It only
advertises SCP03, does not model contactless media and caps applet instances;
these limits are documented in
[`docs/specs/common/toolchain.md`](../docs/specs/common/toolchain.md) §4 and
[`docs/specs/common/research-notes.md`](../docs/specs/common/research-notes.md)
§11.
