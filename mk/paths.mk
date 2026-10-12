# card42 derived paths, source lists and shared helpers.
#
# Included by the top-level Makefile after config/*.mk.  Everything here is
# computed from the configurable variables; nothing in this file is a knob.

empty :=
space := $(empty) $(empty)
comma := ,

# --- Output layout ----------------------------------------------------------
# Deliverables are flat in $(DELIVERABLES): the release CAP/jar is the
# canonical name and the debug CAP carries a -debug suffix.  CAP_MODE
# (config/build.mk) picks which CAP variant the deploy/test targets consume.
DELIVERABLES := $(BUILD_DIR)/deliverables
# Raw converter output, per mode.
OUT_DIR      := $(BUILD_DIR)/out
GEN_DIR      := $(BUILD_DIR)/gen

# Generated compile-time test switch (rule in mk/cap.mk); also part of the EMV
# card source set.
GEN_SRC := $(GEN_DIR)/card42/emv/BuildConfig.java

# --- Card sources -----------------------------------------------------------
CARD_COMMON_SRC := $(shell find $(CARD_COMMON_DIR) -name '*.java')
CARD_EMV_SRC    := $(shell find $(CARD_EMV_DIR) -name '*.java') $(GEN_SRC)
CARD_EMRTD_SRC  := $(shell find $(CARD_EMRTD_DIR) -name '*.java' 2>/dev/null)

# --- External tool paths ----------------------------------------------------
GPAPI         := $(GPAPI_DIR)/$(GPAPI_VERSION)
JC_TOOLS_LIB  := $(JC_HOME_TOOLS)/lib
JC_SIM_CLIENT := $(JC_HOME_SIMULATOR)/client
CONVERTER     := $(JC_HOME_TOOLS)/bin/converter.sh
VERIFYEXP     := $(JC_HOME_TOOLS)/bin/verifyexp.sh

# --- Shared scripts (GPPro and suite loops live here, once) -----------------
GP_SH     := scripts/gp.sh
PERSO_SH  := scripts/perso.sh
RUN_SUITE := scripts/run-suite.sh

# --- Package AIDs in GPPro's plain hex form (ids.mk uses 0x-prefixed) -------
COMMON_PACKAGE_AID_HEX := $(subst :,,$(subst 0x,,$(COMMON_PACKAGE_AID)))
PACKAGE_AID_HEX        := $(subst :,,$(subst 0x,,$(PACKAGE_AID)))
EMRTD_PACKAGE_AID_HEX  := $(subst :,,$(subst 0x,,$(EMRTD_PACKAGE_AID)))

# Base (production) EMV instances plus the test-only instances.
DEPLOY_ALL_CONF := $(DEPLOY_CONF) $(DEPLOY_EMV_TEST_CONF)

# --- Personalization scripts ------------------------------------------------
# The production set is the real-card default; the simulator suites need the
# test instances (04/06/08).  EMV_PERSO_KEYS (the demo SDA profile) is shared.
EMV_PERSO_KEYS        ?= perso/emv/sample.perso.sda.keys
SIM_EMV_PERSO_SCRIPT  ?= perso/emv/sample-test.perso
CARD_EMV_PERSO_SCRIPT ?= perso/emv/sample-j3r180.perso
EMRTD_PERSO_SCRIPT    ?= perso/emrtd/sample.perso

# --- Host tooling -----------------------------------------------------------
MAIN_CLASS       ?= card42.host.emv.cli.Main
EMRTD_MAIN_CLASS ?= card42.host.emrtd.cli.Main

HOST_COMMON_CLASSES    := $(BUILD_DIR)/host/common-classes
HOST_EMV_LIB_CLASSES   := $(BUILD_DIR)/host/emv-lib-classes
HOST_EMV_CLI_CLASSES   := $(BUILD_DIR)/host/emv-cli-classes
HOST_EMRTD_LIB_CLASSES := $(BUILD_DIR)/host/emrtd-lib-classes
HOST_EMRTD_CLI_CLASSES := $(BUILD_DIR)/host/emrtd-cli-classes
HOST_COMMON_STAMP      := $(HOST_COMMON_CLASSES)/.compiled
HOST_EMV_LIB_STAMP     := $(HOST_EMV_LIB_CLASSES)/.compiled
HOST_EMV_CLI_STAMP     := $(HOST_EMV_CLI_CLASSES)/.compiled
HOST_EMRTD_LIB_STAMP   := $(HOST_EMRTD_LIB_CLASSES)/.compiled
HOST_EMRTD_CLI_STAMP   := $(HOST_EMRTD_CLI_CLASSES)/.compiled

# Host-only compilation (no test facilities), used by the five jars.
HOST_COMMON_SRC    := $(shell find host/common -name '*.java')
HOST_EMV_LIB_SRC   := $(shell find host/emv -name '*.java' -not -path 'host/emv/cli/*')
HOST_EMV_CLI_SRC   := $(shell find host/emv/cli -name '*.java' 2>/dev/null)
HOST_EMRTD_LIB_SRC := $(shell find host/emrtd -name '*.java' -not -path 'host/emrtd/cli/*' 2>/dev/null)
HOST_EMRTD_CLI_SRC := $(shell find host/emrtd/cli -name '*.java' 2>/dev/null)
HOST_EMV_SRC       := $(HOST_EMV_LIB_SRC) $(HOST_EMV_CLI_SRC)
HOST_EMRTD_SRC     := $(HOST_EMRTD_LIB_SRC) $(HOST_EMRTD_CLI_SRC)

# Host + card sources compiled together with the tests (unit + integration).
HOST_CLASSES := $(BUILD_DIR)/host/classes
HOST_STAMP   := $(HOST_CLASSES)/.compiled
HOST_SRC          := $(shell find host -name '*.java')
INTEGRATION_SRC   := $(shell find test/emv/integration test/emrtd/integration -name '*.java')
TEST_COMMON_SRC   := $(shell find test/common -name '*.java')
HOST_TEST_SOURCES := $(HOST_SRC) $(INTEGRATION_SRC) $(TEST_COMMON_SRC)
