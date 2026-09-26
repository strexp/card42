# card42

card42 is an EMV + eMRTD toolkit. It ships a shared card-side library CAP, two
card-side applets and three host modules:

| Deliverable | Location | Artifact |
|-------------|----------|----------|
| Shared Java Card library (no applet) | `card/common/` | `card42common.cap` / `.exp` |
| EMV Java Card applet | `card/emv/` | `card42-emv.cap` |
| eMRTD (ICAO 9303) Java Card applet | `card/emrtd/` | `card42-emrtd.cap` |
| Host common library (transport/codec/crypto/util) | `host/common/` | `card42-common.jar` |
| EMV host stack + kernels + CLI | `host/emv/` | `card42-emv.jar` |
| eMRTD host stack + CLI | `host/emrtd/` | `card42-emrtd.jar` |

The business CAPs and jars depend on the shared library/common module.  All
class AIDs derive from the shared private RID `CARD42_RID = 43 41 52 44 42`
("CARDB", configurable in `config/ids.mk`); PSE / PPSE and the ICAO LDS1 DF name
use their standard alias RIDs.

## Scope

**EMV** (`card42-emv`): a minimal EMV payment card — SDA/DDA/CDA offline data
authentication, offline PIN (plaintext and enciphered), issuer authentication,
EMV secure messaging, post-issuance commands and EMV CPS v2.0 personalization —
exposing a contactless Entry Point via a PPSE.  Baseline: **EMV v4.4 Book 1–4
(2022-10)** with **EMV CPS v2.0 (2021-08)** personalization; the contactless
Entry Point implements the **EMV Contactless Book B v2.12** PPSE/combination
subset plus the Book A configuration/pre-processing (Combination Table, Entry
Point Configuration, Pre-Processing Indicators) and the Book B SPI (Annex C);
the kernels reference **Book C-8 v1.2** conceptually.  Default cryptogram
profile CV '5' (3DES), optional CV '6' (AES-128).  The reference host stack
implements both a contact terminal kernel (`ContactKernel`, PSE / direct ADF)
and a contactless one (`ContactlessKernel`, PPSE Entry Point state machine),
sharing one `TransactionFlow`.

**eMRTD** (`card42-emrtd`): ICAO 9303 — the LDS1 file system, **Basic Access
Control**, **ISO/IEC 7816-4 secure messaging**, **Passive Authentication**,
**Active Authentication**, the LDS2 applications (Travel/Visa/Additional
Biometrics records and transparent files), **EF.CardAccess/EF.CardSecurity**
parsing and **Chip Authentication** (ECDH); plus **PACE** (ECDH generic mapping,
3DES and AES-128, MRZ password).  See [`docs/specs/emrtd/`](docs/specs/emrtd/);
EAC 1.11 is the remaining optional item (see [`TODO.emrtd.md`](TODO.emrtd.md)).

## Prerequisites

- A **full JDK** (must contain `bin/javac`; JDK 21 and 25 are known to work).
- Oracle **Java Card Development Kit Tools** and **Simulator**, unpacked under `tools/`.
- **GlobalPlatformPro** at `/usr/share/java/globalplatformpro/gp.jar` (drives both
  simulator and real-card deployment/personalization).
- The reference standards and the toolchain versions are listed in
  [`tools/README.md`](tools/README.md).

Details and tunables: [`docs/specs/common/toolchain.md`](docs/specs/common/toolchain.md) §1–§3.

## Repository layout

```
Makefile      Build (3 CAPs + 3 host jars), verify, simulator and test targets
card/common   Shared Java Card library (`card42.common`)
card/emv      EMV applet (`card42.emv`), depends on card/common
card/emrtd    eMRTD LDS1/LDS2 applet (`card42.emrtd`), depends on card/common
host/common   Shared host library (`card42.host.common`)
host/emv      EMV host stack + kernels + CLI (`card42.host.emv`)
host/emrtd    eMRTD host stack + CLI (`card42.host.emrtd`)
test/common   Fixtures/stubs shared by the unit and integration builds
test/emv      EMV unit + integration suites
test/emrtd    eMRTD unit + integration suites
perso/emv     EMV personalization scripts and key profiles
perso/emrtd   eMRTD personalization script (sample.perso), CSCA/DSC fixtures
deploy/       deploy.conf (both), deploy-emv.conf, deploy-emv-test.conf,
              deploy-emrtd.conf
config/       Tunable build/toolchain/target/ids/simulator/card defaults
docs/         specs/{common,emv,emrtd} (current design)
tools/        Reference standards, Java Card Dev Kit Tools/Simulator, toolchain
              (git-ignored); GlobalPlatformPro is system-provided at
              /usr/share/java/globalplatformpro/gp.jar
build/        Generated output (git-ignored): the CAPs and `card42-*.jar`
```

The full module, package and source layout is in
[`docs/specs/common/architecture.md`](docs/specs/common/architecture.md).

## Build and test

```
make                 # build the three CAPs and the three host jars
make verify          # verify the generated export files
make test-unit       # pure-JVM unit tests (no simulator required)
make test            # both matrix: EMV + eMRTD coexist (no EMV card-block)
make test-emv        # EMV matrix: deploy + personalize + EMV integration suites
make test-emrtd      # eMRTD matrix: LDS1 + LDS2 + BAC + SM + PA + AA + PACE
make TEST_CONTACTLESS=1 test-emv   # contactless flow via the PPSE (test build)
make clean           # remove the build directory
```

`make` produces the CAPs under `build/deliverables/` and the runnable jars
`card42-emv.jar` / `card42-emrtd.jar` (`java -jar ... <command> <subcommand>`,
e.g. `perso export`, `terminal pay`, `terminal emrtd read`).  The complete
target list, simulator and real-card workflows, configuration variables and CLI
usage are in [`docs/specs/common/toolchain.md`](docs/specs/common/toolchain.md).

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/specs/common/`](docs/specs/common/) | Shared design: architecture, toolchain, cryptography, research notes, risks |
| [`docs/specs/emv/`](docs/specs/emv/) | EMV: personalization, transaction flow, contact kernel, contactless Entry Point/PPSE |
| [`docs/specs/emrtd/`](docs/specs/emrtd/) | eMRTD: LDS1/LDS2, BAC, secure messaging, PA, AA, Chip Authentication, PACE, personalization |
| [`TODO.emv.md`](TODO.emv.md) / [`TODO.emrtd.md`](TODO.emrtd.md) | Pending work per module |

## License

LGPL 2.1 — see [`LICENSE`](LICENSE).
