# card42 test targets: simulator/PC-SC integration suites and the pure-JVM unit
# tests (docs/specs/common/toolchain.md §6).
#
# Included by the top-level Makefile after every shared variable is defined, so
# this fragment only carries rules; it must not be used as a standalone makefile
# (`make -C test` will not work, by design).

.PHONY: test test-emv test-emrtd test-emv-sim test-emv-sim-run \
        test-emv-sim-block test-emv-card test-emv-card-all test-unit \
        test-emrtd-card test-emrtd-card-run

# Deployment matrix: EMV-only, eMRTD-only, or both.  The
# suites are grouped per business module; eMRTD integration suites are added
# with the eMRTD host module.
EMV_SUITES   := EmvFlowTest ContactKernelTest DirectoryTest BoundaryTest LogTest VelocityTest \
                AesFlowTest ContactlessTest OnlineClosedLoopTest TerminalCliTest IssuerScriptTest
EMRTD_SUITES := EmrtdBacTest EmrtdLds2IntegrationTest EmrtdLds2AppsIntegrationTest EmrtdPaceIntegrationTest EmrtdChipAuthIntegrationTest EmrtdLds1ChipAuthIntegrationTest


test-emv: test-emv-sim
	@$(MAKE) --no-print-directory test-emv-sim-block

# eMRTD matrix: deploy the LDS1 instance, personalize
# the sample passport and run the BAC + SM + AA integration suite.
test-emrtd: sim-emrtd-install sim-emrtd-perso $(HOST_STAMP)
	@if [ -z "$(EMRTD_SUITES)" ]; then \
	  echo "no eMRTD integration suites (EMRTD_SUITES empty)"; \
	else \
	  for s in $(EMRTD_SUITES); do \
	    echo ">>> $$s"; \
	    $(JAVA) -p $(JC_SIM_CLIENT)/COMService --add-modules ALL-MODULE-PATH \
	      -cp $(HOST_CLASSES) card42.test.$$s -host=socket:localhost:$(SIM_PORT) || exit 1; \
	  done; \
	fi

# "both" matrix: one deployment with the EMV production set
# and the eMRTD LDS1 instance; runs the production EMV suites plus the eMRTD
# suites.  The eMRTD suite reads the CSCA fixture relative to the repo root.
BOTH_EMV_SUITES := ContactKernelTest DirectoryTest
test: sim-install sim-perso $(HOST_STAMP)
	@for s in $(BOTH_EMV_SUITES); do \
	  echo ">>> emv $$s"; \
	  $(JAVA) -p $(JC_SIM_CLIENT)/COMService --add-modules ALL-MODULE-PATH \
	    -cp $(HOST_CLASSES) card42.test.$$s -host=socket:localhost:$(SIM_PORT) || exit 1; \
	done
	@for s in $(EMRTD_SUITES); do \
	  echo ">>> emrtd $$s"; \
	  $(JAVA) -p $(JC_SIM_CLIENT)/COMService --add-modules ALL-MODULE-PATH \
	    -cp $(HOST_CLASSES) card42.test.$$s -host=socket:localhost:$(SIM_PORT) || exit 1; \
	done

# Deploys, personalizes and then runs the contact / contactless smoke test
# (docs/specs/common/toolchain.md §6) plus the directory-structure and command
# boundary tests (docs/specs/common/toolchain.md §6).  Build with TEST_CONTACTLESS=1 to
# exercise the PPSE/contactless flow.
#
# Every suite runs in its own JVM (Checks is process-wide and a failing suite
# exits non-zero), in list order: AesFlowTest and ContactlessTest must precede
# IssuerScriptTest, which blocks the whole card.
test-emv-sim: sim-emv-install sim-emv-perso $(HOST_STAMP)
	cd $(HOST_CLASSES) && for s in $(EMV_SUITES); do \
	  echo ">>> $$s"; \
	  $(HOST_JAVA) card42.test.$$s -host=socket:localhost:$(SIM_PORT) || exit 1; \
	done

# Runs a single integration suite against a running (deployed, personalized)
# simulator, e.g. `make test-emv-sim-run S=AesFlowTest`.  `sim` brings the simulator
# up and personalizes it first, so the suite sees the same state as under
# test-emv-sim.
S ?= EmvFlowTest
test-emv-sim-run: sim-emv-install sim-emv-perso $(HOST_STAMP)
	cd $(HOST_CLASSES) && $(HOST_JAVA) card42.test.$(S) -host=socket:localhost:$(SIM_PORT)

# Runs a single integration suite against a real card over PC/SC, e.g.
# `make test-emv-card S=BoundaryTest` (S defaults to EmvFlowTest).  The CAP must
# already be installed and personalized (`make card-emv-install` / `make card-emv-perso`).
# Not every suite is portable: LogTest depends on jcsl keeping the applet
# selected after a failed SELECT, ContactlessTest needs a contactless reader and
# CardBlockTest has an irreversible effect.
CARD_HOST ?= pcsc
test-emv-card: $(HOST_STAMP)
	@case " $(CARD_PORTABLE_SUITES) " in \
	  *" $(S) "*) ;; \
	  *) echo "test-emv-card: $(S) is not portable to a real card (jcsl-only or contactless);"; \
	     echo "use 'make test-emv-sim-run S=$(S)' against the simulator instead."; \
	     exit 1;; \
	esac
	cd $(HOST_CLASSES) && $(HOST_JAVA) card42.test.$(S) -host=$(CARD_HOST)

# The suites that are portable to a real card, in run order (IssuerScriptTest
# blocks the card and must stay last).  `test-emv-card-all` gates on exactly these,
# so a real-card run does not silently pick up a jcsl-only or contactless suite
# (docs/specs/common/toolchain.md §6).
CARD_PORTABLE_SUITES := EmvFlowTest ContactKernelTest DirectoryTest BoundaryTest \
                        VelocityTest AesFlowTest OnlineClosedLoopTest \
                        TerminalCliTest IssuerScriptTest

test-emv-card-all: $(HOST_STAMP)
	cd $(HOST_CLASSES) && for s in $(CARD_PORTABLE_SUITES); do \
	  echo ">>> $$s"; \
	  $(HOST_JAVA) card42.test.$$s -host=$(CARD_HOST) || exit 1; \
	done

# Runs the eMRTD integration matrix against a real card over PC/SC, e.g.
# `make test-emrtd-card CARD_HOST=pcsc:1` (the reader index defaults to 0, which
# is the SAM slot on the ACR1581; the card is on the PICC reader, index 1).  The
# CAP must already be installed and personalized (`make card-emrtd-install` /
# `make card-emrtd-perso`).  The suites are media-neutral; unlike test-emv-card
# they read the PA CSCA fixture relative to the repo root, so they must run from
# here rather than from $(HOST_CLASSES).
#
#   make test-emrtd-card                 # all EMRTD_SUITES (reader 0)
#   make test-emrtd-card CARD_HOST=pcsc:1
#   make test-emrtd-card-run S=EmrtdBacTest CARD_HOST=pcsc:1   # one suite
#
# The ACR1581 contactless reader intermittently returns 6F00 on the Biometrics
# PACE when a suite follows several others in one run (not reproducible when the
# suite runs standalone), so each suite is retried once; a genuine failure still
# fails the target (TODO.emrtd.md T5.3).
test-emrtd-card: $(HOST_STAMP)
	@for s in $(EMRTD_SUITES); do \
	  echo ">>> $$s"; \
	  $(JAVA) -p $(JC_SIM_CLIENT)/COMService --add-modules ALL-MODULE-PATH \
	    -cp $(HOST_CLASSES) card42.test.$$s -host=$(CARD_HOST) || \
	    { echo ">>> retry $$s (intermittent real-card hiccup)"; sleep 2; \
	      $(JAVA) -p $(JC_SIM_CLIENT)/COMService --add-modules ALL-MODULE-PATH \
	        -cp $(HOST_CLASSES) card42.test.$$s -host=$(CARD_HOST) || exit 1; }; \
	done

test-emrtd-card-run: $(HOST_STAMP)
	@case " $(EMRTD_SUITES) " in \
	  *" $(S) "*) ;; \
	  *) echo "test-emrtd-card-run: $(S) is not an eMRTD suite;"; \
	     echo "choose one of: $(EMRTD_SUITES)"; exit 1;; \
	esac
	$(JAVA) -p $(JC_SIM_CLIENT)/COMService --add-modules ALL-MODULE-PATH \
	  -cp $(HOST_CLASSES) card42.test.$(S) -host=$(CARD_HOST)

# One-command end-to-end verification (docs/specs/common/toolchain.md §6): build,
# configure and start the simulator, deploy every instance in DEPLOY_ALL_CONF,
# personalize over SCP03 and run the smoke test.  Build with
# TEST_CONTACTLESS=1 for the PPSE/contactless flow.
# EmvFlowTest covers SDA, DDA, CDA and the enciphered offline PIN
#
# The CSU Card Block positive test (test-emv-sim-block) needs a fresh simulator
# because the card-wide block is irreversible, so it is run afterwards in a
# second simulator lifecycle.


# CSU "Card Block" (Book 3 Annex C §C10) positive test: restarts a fresh
# simulator, redeploys and re-personalizes, then blocks the card via a CSU with
# a correct ARPC and checks that every subsequent SELECT is refused.
test-emv-sim-block: sim-emv-install sim-emv-perso $(HOST_STAMP)
	cd $(HOST_CLASSES) && $(HOST_JAVA) card42.test.CardBlockTest \
	  -host=socket:localhost:$(SIM_PORT)

# --- Pure-JVM unit tests (docs/specs/common/toolchain.md §6) -----------------------
# No simulator required: the card-side classes are linked against the minimal
# javacard.framework stubs in test/common/stubs (placed before the API jar) and
# the host-side classes run directly.  EMV card-side suites live under
# test/emv/unit/card/{tlv,data,state,risk,perso,crypto} and host-only suites
# under test/emv/unit/host/{codec,crypto,perso,clearing,kernel}/; all share
# package card42.test, so they are collected recursively (test/common holds the
# fixtures/stubs shared with the integration build).
UNIT_DIR      := $(BUILD_DIR)/unit
UNIT_STUBS    := $(UNIT_DIR)/stubs
UNIT_CLASSES  := $(UNIT_DIR)/classes
UNIT_STUB_SRC := $(wildcard test/common/stubs/javacard/framework/*.java) \
                 $(wildcard test/common/stubs/javacard/security/*.java) \
                 $(wildcard test/common/stubs/javacardx/crypto/*.java)
UNIT_SRC      := $(shell find test/emv/unit -name '*.java') \
                 $(shell find test/emrtd/unit -name '*.java') \
                 $(shell find test/common -name '*.java')
UNIT_CARD_SRC := $(CARD_COMMON_DIR)/tlv/Tlv.java $(CARD_COMMON_DIR)/tlv/TlvReader.java \
                 $(CARD_COMMON_DIR)/crypto/ConstantTime.java \
                 $(CARD_COMMON_DIR)/crypto/RetailMac.java \
                 $(CARD_COMMON_DIR)/crypto/AesCmac.java \
                 $(CARD_COMMON_DIR)/crypto/MacAlgorithm.java \
                 $(CARD_COMMON_DIR)/mem/TransientBuffers.java \
                 $(CARD_EMV_DIR)/tlv/DolReader.java \
                 $(CARD_EMV_DIR)/tlv/Dgi.java $(CARD_EMV_DIR)/tlv/DgiReader.java \
                 $(CARD_EMV_DIR)/tlv/TlvTags.java $(CARD_EMV_DIR)/constants/EMVCommands.java \
                 $(CARD_EMV_DIR)/constants/EMVStatus.java $(CARD_EMV_DIR)/constants/EMVRoles.java \
                 $(CARD_EMV_DIR)/constants/EMVCodes.java \
                 $(CARD_EMV_DIR)/mem/EmvScratch.java \
                 $(CARD_EMV_DIR)/state/EMVProtocolState.java \
                 $(CARD_EMV_DIR)/data/EMVStaticData.java $(CARD_EMV_DIR)/data/Defaults.java \
                 $(CARD_EMV_DIR)/data/PaymentData.java $(CARD_EMV_DIR)/data/FciBuilder.java \
                 $(CARD_EMV_DIR)/data/RecordBuilder.java $(CARD_EMV_DIR)/data/DirectoryBuilder.java \
                 $(CARD_EMV_DIR)/data/DirectoryRecords.java \
                 $(CARD_EMV_DIR)/data/SdaCertificateData.java \
                 $(CARD_EMV_DIR)/risk/CardRiskManagement.java \
                 $(CARD_EMV_DIR)/data/Iad.java \
                 $(CARD_EMV_DIR)/data/RecordStore.java \
                 $(CARD_EMV_DIR)/risk/TransactionLog.java \
                 $(CARD_EMV_DIR)/risk/OfflineRisk.java \
                 $(CARD_EMV_DIR)/crypto/CryptoProfile.java \
                 $(CARD_EMV_DIR)/crypto/AcResponseBuilder.java \
                 $(CARD_EMV_DIR)/crypto/EMVCrypto.java \
                 $(CARD_EMV_DIR)/crypto/Arpc.java \
                 $(CARD_EMV_DIR)/crypto/SessionKey.java \
                 $(CARD_EMV_DIR)/crypto/SecureMessaging.java \
                 $(CARD_EMV_DIR)/perso/PersoErrors.java \
                 $(CARD_EMV_DIR)/perso/PersoRules.java \
                 $(CARD_EMV_DIR)/applet/InstallParameters.java \
                 $(CARD_EMRTD_DIR)/tlv/EmrtdTags.java \
                 $(CARD_EMRTD_DIR)/crypto/P256.java \
                 $(CARD_EMRTD_DIR)/crypto/Sha1Kdf.java \
                 $(CARD_EMRTD_DIR)/access/MrzKeySeed.java \
                 $(CARD_EMRTD_DIR)/access/BacCrypto.java \
                 $(CARD_EMRTD_DIR)/access/Iso7816Sm.java \
                 $(CARD_EMRTD_DIR)/access/Iso7816SmAes.java \
                 $(CARD_EMRTD_DIR)/access/SecureMessaging.java \
                 $(CARD_EMRTD_DIR)/access/AbstractSecureMessaging.java \
                 $(CARD_EMRTD_DIR)/access/SmScratch.java \
                 $(CARD_EMRTD_DIR)/crypto/AaCrypto.java \
                 $(CARD_EMRTD_DIR)/lds/LdsFile.java \
                 $(CARD_EMRTD_DIR)/lds/LdsFileSystem.java \
                 $(CARD_EMRTD_DIR)/lds/LdsCatalog.java \
                 $(CARD_EMRTD_DIR)/lds/Lds2TransparentFile.java \
                 $(CARD_EMRTD_DIR)/lds/Lds2RecordFile.java \
                 $(CARD_EMRTD_DIR)/lds/Lds2FileSystem.java \
                 $(CARD_EMRTD_DIR)/lds/LdsMfStore.java \
                 $(CARD_EMRTD_DIR)/lds/DgiStream.java \
                 $(CARD_EMRTD_DIR)/lds/LdsPerso.java \
                 $(CARD_EMRTD_DIR)/lds/Lds2Perso.java \
                 $(CARD_EMRTD_DIR)/access/ChipAuth.java \
                 $(CARD_EMRTD_DIR)/access/PaceSeedSink.java \
                 $(CARD_COMMON_DIR)/applet/ApduIo.java \
                 $(CARD_COMMON_DIR)/applet/AppletBase.java \
                 $(CARD_EMRTD_DIR)/applet/EmrtdInstallParameters.java \
                 $(CARD_EMRTD_DIR)/mem/EmrtdScratch.java \
                 $(CARD_EMRTD_DIR)/applet/EmrtdApplet.java \
                 $(CARD_EMRTD_DIR)/command/ExternalAuthenticate.java \
                 $(CARD_EMRTD_DIR)/command/GetChallenge.java \
                 $(CARD_EMRTD_DIR)/command/InternalAuthenticate.java \
                 $(CARD_EMRTD_DIR)/command/Lds2Record.java \
                 $(CARD_EMRTD_DIR)/command/Mse.java \
                 $(CARD_EMRTD_DIR)/command/ReadBinary.java \
                 $(CARD_EMRTD_DIR)/command/SelectFile.java
UNIT_HOST_SRC := $(HOST_LIB_SRC)
# The applet implements org.globalplatform.Personalization (GP API 1.6), so the
# GP API jar links the command-level card tests in the pure-JVM unit build.
GPAPI_JAR     := $(GPAPI)/gpapi-globalplatform.jar
UNIT_CP       := $(UNIT_CLASSES):$(UNIT_STUBS):$(JC_TOOLS_LIB)/api_classic-$(JC_API_VERSION).jar:$(GPAPI_JAR)
UNIT_STUB_STAMP  := $(UNIT_STUBS)/.compiled
UNIT_CLASS_STAMP := $(UNIT_CLASSES)/.compiled

$(UNIT_STUB_STAMP): $(UNIT_STUB_SRC)
	@mkdir -p $(UNIT_STUBS)
	$(JAVAC) -d $(UNIT_STUBS) $(UNIT_STUB_SRC)
	@touch $@

$(UNIT_CLASS_STAMP): $(UNIT_STUB_STAMP) $(UNIT_CARD_SRC) $(UNIT_HOST_SRC) $(UNIT_SRC)
	@mkdir -p $(UNIT_CLASSES)
	$(JAVAC) -d $(UNIT_CLASSES) \
	  -cp $(UNIT_STUBS):$(JC_TOOLS_LIB)/api_classic-$(JC_API_VERSION).jar:$(GPAPI_JAR) \
	  $(UNIT_CARD_SRC) $(UNIT_HOST_SRC) $(UNIT_SRC)
	@touch $@

test-unit: $(UNIT_CLASS_STAMP)
	$(JAVA) -cp $(UNIT_CP) card42.test.UnitTests
