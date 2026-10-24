# card42 integration tests: simulator (socket) and real card (PC/SC).
#
# Naming -- the same shape for every module keyword <mod> = emv | emrtd | both:
#
#   test-<mod>-sim            deploy + personalize + every module suite
#   test-<mod>-sim-run S=     deploy + personalize + one suite
#   test-<mod>-card           run the module suites on a real card
#   test-<mod>-card-run S=    run one suite on a real card
#
# The suite loops live in scripts/run-suite.sh; each suite runs in its own JVM
# (Checks is process-wide and a failing suite exits non-zero).  EMV sim/card
# suites run from $(HOST_CLASSES); the eMRTD PA CSCA fixture is read relative to
# the repo root, so the eMRTD and both matrices run from there.
#
# test-emv-sim runs the EMV suites and then CardBlockTest in a SECOND simulator
# lifecycle: the card block is irreversible and IssuerScriptTest (last in
# EMV_SUITES) already blocks the first card, so CardBlockTest needs a freshly
# deployed, personalized card to exercise the CSU card-block path.

.PHONY: test-emv-sim test-emv-sim-run test-emrtd-sim test-emrtd-sim-run \
        test-both-sim test-emv-card test-emv-card-run \
        test-emrtd-card test-emrtd-card-run test-both-card

# Suites per module.  Order matters: AesFlowTest and ContactlessTest must
# precede IssuerScriptTest, which blocks the whole card and therefore stays
# last.  CardBlockTest is not listed here; test-emv-sim runs it on a fresh
# simulator after these (see above).
EMV_SUITES   := EmvFlowTest ContactKernelTest DirectoryTest BoundaryTest LogTest VelocityTest \
                AesFlowTest ContactlessTest OnlineClosedLoopTest TerminalCliTest IssuerScriptTest
EMRTD_SUITES := EmrtdBacTest EmrtdCvcaTest EmrtdLds2IntegrationTest EmrtdLds2AppsIntegrationTest EmrtdLds2WriteIntegrationTest EmrtdLds2OpsIntegrationTest EmrtdLds2AlgorithmsIntegrationTest EmrtdLds2CliIntegrationTest EmrtdPaceIntegrationTest EmrtdChipAuthIntegrationTest EmrtdChipAuthAesIntegrationTest EmrtdTaAlgorithmsIntegrationTest EmrtdLds1ChipAuthIntegrationTest EmrtdTerminalAuthIntegrationTest EmrtdPerfTest
# Simulator-only eMRTD suites: they rely on the demo personalization (all
# data groups, TA trust point) and are not part of the real-card matrix.
EMRTD_SIM_SUITES := EmrtdLdsParsersIntegrationTest
EMRTD_ALL_SIM_SUITES := $(EMRTD_SUITES) $(EMRTD_SIM_SUITES)

# Both matrix: a single coexistence deployment runs the production EMV suites
# that need only the production instances (the test instances 04/06/08 are not
# deployed) plus the eMRTD suites.  BoundaryTest/LogTest/VelocityTest need 06,
# AesFlowTest 08; IssuerScriptTest and CardBlockTest would block the card.
BOTH_EMV_SUITES := EmvFlowTest ContactKernelTest DirectoryTest \
                   OnlineClosedLoopTest TerminalCliTest

# EMV suites portable to a real card: excludes the jcsl-only LogTest, the
# contactless ContactlessTest, and every card-blocking suite (IssuerScriptTest
# and CardBlockTest are irreversible and stay off real cards entirely).
CARD_PORTABLE_SUITES := EmvFlowTest ContactKernelTest DirectoryTest BoundaryTest \
                        VelocityTest AesFlowTest OnlineClosedLoopTest TerminalCliTest

# Defaults for the single-suite selectors and the real-card reader.
S ?= EmvFlowTest
CARD_HOST ?= pcsc

# run-suite.sh environment (variables collapse to one line).
SIM_ENV   := SUITE_JAVA="$(JAVA)" SUITE_CLASSES="$(abspath $(HOST_CLASSES))" \
             COM_SERVICE="$(abspath $(JC_SIM_CLIENT)/COMService)" \
             SUITE_HOST="socket:localhost:$(SIM_PORT)"
CARD_ENV  := SUITE_JAVA="$(JAVA)" SUITE_CLASSES="$(abspath $(HOST_CLASSES))" \
             COM_SERVICE="$(abspath $(JC_SIM_CLIENT)/COMService)" \
             SUITE_HOST="$(CARD_HOST)"
CLASSES_CWD := SUITE_CWD="$(abspath $(HOST_CLASSES))"
ROOT_CWD    := SUITE_CWD="$(CURDIR)"

# --- Simulator --------------------------------------------------------------
test-emv-sim: sim-emv-install sim-emv-perso $(HOST_STAMP)
	$(SIM_ENV) $(CLASSES_CWD) $(RUN_SUITE) $(EMV_SUITES)
	@echo ">>> CardBlockTest (fresh simulator)"
	@$(MAKE) --no-print-directory sim-emv-install sim-emv-perso
	$(SIM_ENV) $(CLASSES_CWD) $(RUN_SUITE) CardBlockTest

# Runs one EMV suite against the deployed, personalized simulator.
test-emv-sim-run: sim-emv-install sim-emv-perso $(HOST_STAMP)
	@case " $(EMV_SUITES) " in \
	  *" $(S) "*) ;; \
	  *) echo "test-emv-sim-run: $(S) is not an EMV suite;"; \
	     echo "choose one of: $(EMV_SUITES)"; exit 1;; \
	esac
	$(SIM_ENV) $(CLASSES_CWD) $(RUN_SUITE) $(S)

test-emrtd-sim: sim-emrtd-install sim-emrtd-perso $(HOST_STAMP)
	$(SIM_ENV) $(ROOT_CWD) $(RUN_SUITE) $(EMRTD_ALL_SIM_SUITES)

test-emrtd-sim-run: sim-emrtd-install sim-emrtd-perso $(HOST_STAMP)
	@case " $(EMRTD_ALL_SIM_SUITES) " in \
	  *" $(S) "*) ;; \
	  *) echo "test-emrtd-sim-run: $(S) is not an eMRTD simulator suite;"; \
	     echo "choose one of: $(EMRTD_ALL_SIM_SUITES)"; exit 1;; \
	esac
	$(SIM_ENV) $(ROOT_CWD) $(RUN_SUITE) $(S)

test-both-sim: sim-both-install sim-both-perso $(HOST_STAMP)
	$(SIM_ENV) $(ROOT_CWD) $(RUN_SUITE) $(BOTH_EMV_SUITES)
	$(SIM_ENV) $(ROOT_CWD) $(RUN_SUITE) $(EMRTD_ALL_SIM_SUITES)

# --- Real card --------------------------------------------------------------
# The CAP must already be installed and personalized (card-<mod>-install /
# card-<mod>-perso).
test-emv-card: $(HOST_STAMP)
	$(CARD_ENV) $(CLASSES_CWD) $(RUN_SUITE) $(CARD_PORTABLE_SUITES)

test-emv-card-run: $(HOST_STAMP)
	@case " $(CARD_PORTABLE_SUITES) " in \
	  *" $(S) "*) ;; \
	  *) echo "test-emv-card-run: $(S) is not portable to a real card (jcsl-only, contactless or card-blocking);"; \
	     echo "use 'make test-emv-sim-run S=$(S)' against the simulator instead."; exit 1;; \
	esac
	$(CARD_ENV) $(CLASSES_CWD) $(RUN_SUITE) $(S)

test-emrtd-card: $(HOST_STAMP)
	$(CARD_ENV) $(ROOT_CWD) $(RUN_SUITE) $(EMRTD_SUITES)

test-emrtd-card-run: $(HOST_STAMP)
	@case " $(EMRTD_SUITES) " in \
	  *" $(S) "*) ;; \
	  *) echo "test-emrtd-card-run: $(S) is not an eMRTD suite;"; \
	     echo "choose one of: $(EMRTD_SUITES)"; exit 1;; \
	esac
	$(CARD_ENV) $(ROOT_CWD) $(RUN_SUITE) $(S)

test-both-card: $(HOST_STAMP)
	$(CARD_ENV) $(ROOT_CWD) $(RUN_SUITE) $(BOTH_EMV_SUITES)
	$(CARD_ENV) $(ROOT_CWD) $(RUN_SUITE) $(EMRTD_SUITES)
