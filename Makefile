# card42 - Java Card applet (CAP) + host reference stack (jar) build
#
# Overridable configuration (examples):
#   make JAVA_HOME=/path/to/jdk        (must be a full JDK, i.e. contain bin/javac)
#   make JC_HOME_TOOLS=/opt/jc-tools JC_HOME_SIMULATOR=/opt/jc-sim
#   make JC_TARGET=3.1.0 JC_API_VERSION=3.1.0
#   make TEST_CONTACTLESS=1            (test build, see docs/specs/common/architecture.md §7)
#   make sim-emv-install SIM_KVN=01 SIM_ENC_KEY=... SIM_MAC_KEY=... SIM_DEK_KEY=...
#
# The tunable defaults live in config/*.mk (one file per category).  Copy
# config/local.mk.example to config/local.mk for persistent local overrides;
# command-line assignments always win over both.

# --- Configuration ----------------------------------------------------------
# local.mk is loaded first so its values take precedence over the per-category
# defaults below; the command line and the environment still win over both.
CONFIG_DIR   := config
CONFIG_FILES := $(wildcard $(CONFIG_DIR)/*.mk)
-include $(CONFIG_DIR)/local.mk
include $(CONFIG_DIR)/build.mk
include $(CONFIG_DIR)/toolchain.mk
include $(CONFIG_DIR)/externals.mk
include $(CONFIG_DIR)/target.mk
include $(CONFIG_DIR)/ids.mk
include $(CONFIG_DIR)/simulator.mk
include $(CONFIG_DIR)/card.mk

# --- Derived paths ----------------------------------------------------------
empty :=
space := $(empty) $(empty)
comma := ,
BIN_DIR      := $(BUILD_DIR)/bin
GEN_DIR      := $(BUILD_DIR)/gen
DELIVERABLES := $(BUILD_DIR)/deliverables

# card42common library CAP
COMMON_BIN      := $(BUILD_DIR)/card/common/bin
COMMON_OUT      := $(DELIVERABLES)/card42common
COMMON_CAP_FILE := $(COMMON_OUT)/card42/common/javacard/common.cap
COMMON_EXP_FILE := $(COMMON_OUT)/card42/common/javacard/common.exp
COMMON_CONF     := $(BUILD_DIR)/card42common.conf

# card42-emv CAP
EMV_BIN      := $(BUILD_DIR)/card/emv/bin
EMV_CAP_FILE := $(DELIVERABLES)/card42/emv/javacard/emv.cap
EMV_EXP_FILE := $(DELIVERABLES)/card42/emv/javacard/emv.exp
EMV_CONF     := $(BUILD_DIR)/card42-emv.conf

# card42-emrtd CAP
EMRTD_BIN      := $(BUILD_DIR)/card/emrtd/bin
EMRTD_CAP_FILE := $(DELIVERABLES)/card42/emrtd/javacard/emrtd.cap
EMRTD_EXP_FILE := $(DELIVERABLES)/card42/emrtd/javacard/emrtd.exp
EMRTD_CONF     := $(BUILD_DIR)/card42-emrtd.conf

# Backward-compatible aliases (the EMV CAP is the default card deliverable).
CAP_FILE  := $(EMV_CAP_FILE)
EXP_FILE  := $(EMV_EXP_FILE)
CONF_FILE := $(EMV_CONF)
GEN_SRC   := $(GEN_DIR)/card42/emv/BuildConfig.java

# Host three-module deliverables: card42-common.jar is the
# shared library; card42-emv.jar / card42-emrtd.jar are independently runnable
# and carry a Class-Path manifest entry pointing at common.
HOST_COMMON_JAR := $(DELIVERABLES)/card42-common.jar
HOST_EMV_JAR    := $(DELIVERABLES)/card42-emv.jar
HOST_EMRTD_JAR  := $(DELIVERABLES)/card42-emrtd.jar
MAIN_CLASS      ?= card42.host.emv.cli.Main

GPAPI         := $(GPAPI_DIR)/$(GPAPI_VERSION)
JC_TOOLS_LIB  := $(JC_HOME_TOOLS)/lib
JC_SIM_CLIENT := $(JC_HOME_SIMULATOR)/client

# Package AIDs in GPPro's plain hex form (ids.mk uses 0x-prefixed, colon-separated).
PACKAGE_AID_HEX       := $(subst :,,$(subst 0x,,$(PACKAGE_AID)))
EMRTD_PACKAGE_AID_HEX := $(subst :,,$(subst 0x,,$(EMRTD_PACKAGE_AID)))

# Base (production) instances plus the test-only instances in deploy/deploy-test.conf.
DEPLOY_ALL_CONF := $(DEPLOY_CONF) $(DEPLOY_EMV_TEST_CONF)

# Personalization scripts (docs/specs/common/toolchain.md §5).  The production set is the
# real-card default; the simulator suites need the test instances (04/06/08), so
# the simulator uses the test set.  EMV_PERSO_KEYS (the demo SDA profile) is shared.
EMV_PERSO_KEYS        ?= perso/emv/sample.perso.sda.keys
SIM_EMV_PERSO_SCRIPT  ?= perso/emv/sample-test.perso
CARD_EMV_PERSO_SCRIPT ?= perso/emv/sample-j3r180.perso
EMRTD_PERSO_SCRIPT ?= perso/emrtd/sample.perso

# --- Source -----------------------------------------------------------------
CARD_COMMON_SRC := $(shell find $(CARD_COMMON_DIR) -name '*.java')
CARD_EMV_SRC    := $(shell find $(CARD_EMV_DIR) -name '*.java') $(GEN_SRC)
CARD_EMRTD_SRC  := $(shell find $(CARD_EMRTD_DIR) -name '*.java' 2>/dev/null)
SOURCES    := $(CARD_EMV_SRC)

# --- Simulator paths --------------------------------------------------------
SIM_DIR      ?= $(BUILD_DIR)/sim
SIM_BIN      := $(SIM_DIR)/jcsl
SIM_LOG      := $(SIM_DIR)/simulator.log
SIM_PID      := $(SIM_DIR)/simulator.pid

# Compiled host tooling and tests (package card42.host.* / card42.test).
HOST_CLASSES := $(BUILD_DIR)/host/classes
HOST_STAMP   := $(HOST_CLASSES)/.compiled

# Host-only compilation (no test facilities), used to build the three jars and
# to compile the unit tests.
HOST_COMMON_SRC  := $(shell find host/common -name '*.java')
HOST_EMV_SRC     := $(shell find host/emv -name '*.java')
HOST_EMRTD_SRC   := $(shell find host/emrtd -name '*.java' 2>/dev/null)
HOST_LIB_SRC     := $(HOST_COMMON_SRC) $(HOST_EMV_SRC) $(HOST_EMRTD_SRC)
HOST_COMMON_CLASSES := $(BUILD_DIR)/host/common-classes
HOST_EMV_CLASSES    := $(BUILD_DIR)/host/emv-classes
HOST_EMRTD_CLASSES  := $(BUILD_DIR)/host/emrtd-classes
HOST_COMMON_STAMP   := $(HOST_COMMON_CLASSES)/.compiled
HOST_EMV_STAMP      := $(HOST_EMV_CLASSES)/.compiled
HOST_EMRTD_STAMP    := $(HOST_EMRTD_CLASSES)/.compiled
HOST_LIB_CLASSES    := $(BUILD_DIR)/host/lib-classes
HOST_LIB_STAMP      := $(BUILD_DIR)/host/lib.stamp

# Shared host JVM invocation.  The `cd $(HOST_CLASSES)` is deliberately kept
# out of this variable: the suite loop below changes directory once and then
# runs every suite, so a relative cd must not be repeated per iteration.  Only
# the COMService module is needed (the `socket:` transport of the integration
# suites, docs/specs/common/toolchain.md §6); deployment/personalization go through
# GPPro, so the simulator's own AMS modules are no longer on the path.
HOST_JAVA := $(JAVA) -p $(JC_SIM_CLIENT)/COMService \
              --add-modules ALL-MODULE-PATH -cp .

.PHONY: all card card-common card-emv card-emrtd cap jar classes convert verify clean \
        host host-common host-emv host-emrtd \
        sim-install sim-perso sim-emv-install sim-emv-perso \
        sim-emrtd-install sim-emrtd-perso \
        sim-configure sim-start sim-wait sim-stop \
        card-install card-perso card-emv-install card-emv-perso \
        card-emrtd-install card-emrtd-perso card-keychange card-uninstall FORCE

all: card jar

# Card deliverables: the library CAP must precede the
# business CAPs.
card: card-common card-emv card-emrtd
card-common: $(COMMON_CAP_FILE)
card-emv: $(EMV_CAP_FILE)
card-emrtd: $(EMRTD_CAP_FILE)
cap: card
classes: card

# Test targets live in test/rules.mk (included after the shared variables above
# so that fragment can use them).  See docs/specs/common/toolchain.md §6.
include test/rules.mk

# Generates the compile-time test switch.  The recipe runs on every invocation
# (FORCE) but only rewrites the file when the value actually changed, so it does
# not force a CAP rebuild when nothing changed.
$(GEN_SRC): FORCE
	@mkdir -p $(dir $@)
	@if [ "$(TEST_CONTACTLESS)" = "1" ]; then v=true; else v=false; fi; \
	if [ ! -f $@ ] || ! grep -q "ALLOW_CONTACTLESS_ON_CONTACT = $$v;" $@; then \
	  echo "generating $@ (ALLOW_CONTACTLESS_ON_CONTACT=$$v)"; \
	  { \
	    echo 'package card42.emv;'; \
	    echo ''; \
	    echo '/* Generated by the Makefile.  Do not edit; see docs/specs/common/architecture.md §7. */'; \
	    echo 'public final class BuildConfig {'; \
	    echo '    /** Test build only: allow CONTACTLESS role instances on the contact interface. */'; \
	    echo "    public static final boolean ALLOW_CONTACTLESS_ON_CONTACT = $$v;"; \
	    echo ''; \
	    echo '    private BuildConfig() {}'; \
	    echo '}'; \
	  } > $@; \
	fi

FORCE:

# --- card42common library CAP ---------------------------
$(COMMON_CONF): Makefile $(CONFIG_FILES)
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '-classdir card/common/bin' \
	  '-exportpath $(abspath $(GPAPI)/exports23)' \
	  '-out CAP EXP JCA' \
	  '-d deliverables/card42common' \
	  '-debug' \
	  '-target $(JC_TARGET)' \
	  '$(COMMON_PACKAGE_NAME)' \
	  '$(COMMON_PACKAGE_AID) $(COMMON_VERSION)' > $@

$(COMMON_CAP_FILE): $(CARD_COMMON_SRC) $(COMMON_CONF)
	@mkdir -p $(COMMON_BIN)
	$(JAVAC) -g -d $(COMMON_BIN) \
	  -cp $(JC_TOOLS_LIB)/api_classic-$(JC_API_VERSION).jar:$(GPAPI)/gpapi-globalplatform.jar \
	  --release $(JAVAC_RELEASE) -Xlint:-options \
	  -encoding UTF-8 \
	  $(CARD_COMMON_SRC)
	@rm -rf $(COMMON_OUT)
	cd $(BUILD_DIR) && JAVA_HOME="$(JAVA_HOME)" $(JC_HOME_TOOLS)/bin/converter.sh -config card42common.conf

# --- card42-emv CAP -------------------------------------
$(EMV_CONF): Makefile $(CONFIG_FILES)
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '-classdir card/emv/bin' \
	  '-exportpath $(abspath $(GPAPI)/exports23):$(abspath $(COMMON_OUT))' \
	  '-applet $(APPLET_AID) $(APPLET_CLASS)' \
	  '-applet $(DIRECTORY_AID) $(DIRECTORY_CLASS)' \
	  '-out CAP EXP JCA' \
	  '-d deliverables' \
	  '-debug' \
	  '-target $(JC_TARGET)' \
	  '$(PACKAGE_NAME)' \
	  '$(PACKAGE_AID) $(PACKAGE_VERSION)' > $@

$(EMV_CAP_FILE): $(CARD_EMV_SRC) $(COMMON_CAP_FILE) $(EMV_CONF)
	@mkdir -p $(EMV_BIN)
	$(JAVAC) -g -d $(EMV_BIN) \
	  -cp $(JC_TOOLS_LIB)/api_classic-$(JC_API_VERSION).jar:$(GPAPI)/gpapi-globalplatform.jar:$(COMMON_BIN) \
	  --release $(JAVAC_RELEASE) -Xlint:-options \
	  -encoding UTF-8 \
	  $(CARD_EMV_SRC)
	@rm -rf $(DELIVERABLES)/card42
	cd $(BUILD_DIR) && JAVA_HOME="$(JAVA_HOME)" $(JC_HOME_TOOLS)/bin/converter.sh -config card42-emv.conf

# --- card42-emrtd CAP -------------------------------------
$(EMRTD_CONF): Makefile $(CONFIG_FILES)
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '-classdir card/emrtd/bin' \
	  '-exportpath $(abspath $(GPAPI)/exports23):$(abspath $(COMMON_OUT))' \
	  '-applet $(EMRTD_AID) $(EMRTD_CLASS)' \
	  '-out CAP EXP JCA' \
	  '-d deliverables' \
	  '-debug' \
	  '-target $(JC_TARGET)' \
	  '$(EMRTD_PACKAGE_NAME)' \
	  '$(EMRTD_PACKAGE_AID) 1.0' > $@

$(EMRTD_CAP_FILE): $(CARD_EMRTD_SRC) $(COMMON_CAP_FILE) $(EMRTD_CONF)
	@if [ -n "$(CARD_EMRTD_SRC)" ]; then \
	  mkdir -p $(EMRTD_BIN); \
	  $(JAVAC) -g -d $(EMRTD_BIN) \
	    -cp $(JC_TOOLS_LIB)/api_classic-$(JC_API_VERSION).jar:$(GPAPI)/gpapi-globalplatform.jar:$(COMMON_BIN) \
	    --release $(JAVAC_RELEASE) -Xlint:-options -encoding UTF-8 \
	    $(CARD_EMRTD_SRC) || exit 1; \
	  rm -rf $(DELIVERABLES)/card42/emrtd; \
	  cd $(BUILD_DIR) && JAVA_HOME="$(JAVA_HOME)" $(JC_HOME_TOOLS)/bin/converter.sh -config card42-emrtd.conf; \
	fi

convert: card

verify: card-common card-emv card-emrtd
	JAVA_HOME="$(JAVA_HOME)" $(JC_HOME_TOOLS)/bin/verifyexp.sh $(abspath $(COMMON_EXP_FILE))
	JAVA_HOME="$(JAVA_HOME)" $(JC_HOME_TOOLS)/bin/verifyexp.sh $(abspath $(EMV_EXP_FILE))
	@if [ -f $(EMRTD_EXP_FILE) ]; then \
	  JAVA_HOME="$(JAVA_HOME)" $(JC_HOME_TOOLS)/bin/verifyexp.sh $(abspath $(EMRTD_EXP_FILE)); \
	fi

# --- Host three modules ---------------------------------
# card42-common.jar (library), card42-emv.jar (CLI card42.host.emv.cli.Main) and
# card42-emrtd.jar (CLI card42.host.emrtd.cli.Main).  The business jars carry a
# Class-Path manifest entry so `java -jar card42-emv.jar ...` finds common when
# the three jars sit in the same directory.
jar: host
host: host-common host-emv host-emrtd

host-common: $(HOST_COMMON_JAR)
host-emv: $(HOST_EMV_JAR)
host-emrtd: $(HOST_EMRTD_JAR)

$(HOST_COMMON_STAMP): $(HOST_COMMON_SRC)
	@mkdir -p $(HOST_COMMON_CLASSES)
	$(JAVAC) -d $(HOST_COMMON_CLASSES) $(HOST_COMMON_SRC)
	@touch $@

$(HOST_COMMON_JAR): $(HOST_COMMON_STAMP)
	@mkdir -p $(dir $@)
	$(JAR) cf $@ -C $(HOST_COMMON_CLASSES) .

$(HOST_EMV_STAMP): $(HOST_EMV_SRC) $(HOST_COMMON_STAMP)
	@mkdir -p $(HOST_EMV_CLASSES)
	$(JAVAC) -cp $(HOST_COMMON_CLASSES) -d $(HOST_EMV_CLASSES) $(HOST_EMV_SRC)
	@touch $@

$(HOST_EMV_JAR): $(HOST_EMV_STAMP)
	@mkdir -p $(dir $@)
	@printf 'Manifest-Version: 1.0\nMain-Class: %s\nClass-Path: card42-common.jar\n\n' \
	  '$(MAIN_CLASS)' > $(BUILD_DIR)/emv.mf
	$(JAR) cfm $@ $(BUILD_DIR)/emv.mf -C $(HOST_EMV_CLASSES) .

# eMRTD host module (built only once host/emrtd exists).
$(HOST_EMRTD_STAMP): $(HOST_EMRTD_SRC) $(HOST_COMMON_STAMP)
	@if [ -n "$(HOST_EMRTD_SRC)" ]; then \
	  mkdir -p $(HOST_EMRTD_CLASSES); \
	  $(JAVAC) -cp $(HOST_COMMON_CLASSES) -d $(HOST_EMRTD_CLASSES) $(HOST_EMRTD_SRC); \
	  touch $@; \
	fi

$(HOST_EMRTD_JAR): $(HOST_EMRTD_STAMP)
	@if [ -n "$(HOST_EMRTD_SRC)" ]; then \
	  mkdir -p $(dir $@); \
	  printf 'Manifest-Version: 1.0\nMain-Class: card42.host.emrtd.cli.Main\nClass-Path: card42-common.jar\n\n' \
	    > $(BUILD_DIR)/emrtd.mf; \
	  $(JAR) cfm $@ $(BUILD_DIR)/emrtd.mf -C $(HOST_EMRTD_CLASSES) .; \
	fi

# Host sources compiled together with the tests (unit + integration).
$(HOST_LIB_STAMP): $(HOST_LIB_SRC)
	@mkdir -p $(HOST_LIB_CLASSES)
	$(JAVAC) -d $(HOST_LIB_CLASSES) $(HOST_LIB_SRC)
	@touch $@

# --- Simulator --------------------------------------------------------------
# `*-install` = LOAD the CAP(s) + CREATE the instances; personalization is the
# separate `*-perso` step.  No suffix installs both modules, `-emv`/`-emrtd`
# select one.  (`deploy` is no longer a target name; the simulator and real-card
# flows share the same `install`/`perso` vocabulary.)

sim-configure: sim-stop
	@mkdir -p $(SIM_DIR)
	cp $(JC_HOME_SIMULATOR)/runtime/bin/jcsl $(SIM_BIN)
	$(JAVA) -jar $(JC_HOME_SIMULATOR)/tools/Configurator.jar \
	  -binary $(SIM_BIN) -force \
	  -SCP-keyset $(SIM_KVN) $(SIM_ENC_KEY) $(SIM_MAC_KEY) $(SIM_DEK_KEY) \
	  -global-pin $(SIM_GLOBAL_PIN) $(SIM_PIN_TRIES)

sim-start: sim-configure
	@LD_LIBRARY_PATH=$(JC_HOME_SIMULATOR)/runtime/bin \
	  OPENSSL_MODULES=$(JC_HOME_SIMULATOR)/runtime/bin \
	  setsid $(SIM_BIN) -p=$(SIM_PORT) \
	  > $(SIM_LOG) 2>&1 < /dev/null & echo $$! > $(SIM_PID); \
	  echo "simulator started on port $(SIM_PORT)"

sim-wait: sim-start
	@for i in $$(seq 1 60); do \
	  grep -q "server ready on port" $(SIM_LOG) 2>/dev/null && exit 0; \
	  if grep -q "failed to bind server socket" $(SIM_LOG) 2>/dev/null; then \
	    echo "simulator could not bind port $(SIM_PORT): another jcsl may still be running"; \
	    echo "see $(SIM_LOG)"; exit 1; \
	  fi; \
	  sleep 0.5; \
	done; echo "simulator did not start, see $(SIM_LOG)"; exit 1

# Host-side Java sources: host/common (package
# card42.host.common.*), host/emv (card42.host.emv.*) and host/emrtd
# (card42.host.emrtd.*).  test/emv/integration/ holds the EMV integration suites
# and their test doubles/helpers; test/common/ holds the fixtures/stubs shared
# with the unit build (package card42.test).
HOST_SRC          := $(shell find host -name '*.java')
INTEGRATION_SRC   := $(shell find test/emv/integration test/emrtd/integration -name '*.java')
TEST_COMMON_SRC   := $(shell find test/common -name '*.java')
HOST_TEST_SOURCES := $(HOST_SRC) $(INTEGRATION_SRC) $(TEST_COMMON_SRC)

$(HOST_STAMP): $(HOST_TEST_SOURCES)
	@mkdir -p $(HOST_CLASSES)
	$(JAVAC) -cp $(JC_SIM_CLIENT)/COMService/socketprovider.jar \
	  -d $(HOST_CLASSES) $(HOST_TEST_SOURCES)
	@touch $@

# Installation of the simulator goes through the same GPPro binary as a real
# card; only the transport differs (docs/specs/common/toolchain.md §4).
# GP_SIM selects nextgen over the jcsl socket (config/simulator.mk); a card uses
# the default PC/SC transport.  The CAP is only LOADed (never auto-installed) so
# instance AIDs match deploy/deploy.conf exactly.  `--create` cannot reliably infer
# the package from the applet AID (neither the nextgen nor the classic path, since
# the applet is not yet in the registry), so it is passed explicitly.
sim-emv-install: sim-wait card-common card-emv
	@for cap in $(subst $(comma), ,$(SIM_CAPS)); do \
	  echo ">>> load $$cap"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --load $$cap || exit 1; \
	done
	@awk '!/^[[:space:]]*#/ && NF >= 2 { print $$1, $$2 }' $(DEPLOY_ALL_CONF) | \
	while read -r instance class; do \
	  echo ">>> create $$instance (applet $$class)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --create $$instance --applet $$class \
	    --package $(PACKAGE_AID_HEX) || exit 1; \
	done

# GP personalization (docs/specs/emv/personalization.md §1) of the instances listed in
# $(SIM_EMV_PERSO_SCRIPT) (production + test set, since the suites use 04/06/08), via
# GPPro `--personalize <AID> --store-data <hex>` (the same path as a real card,
# SCP03 on the simulator).  Assumes the simulator is already running and
# deployed; use `make sim-emv-install sim-emv-perso` or `make test-emv-sim`.
sim-emv-perso: $(HOST_STAMP)
	@lines=$$($(JAVA) -cp $(HOST_CLASSES) card42.host.emv.cli.Main perso export \
	    -script=$(abspath $(SIM_EMV_PERSO_SCRIPT)) -keys=$(abspath $(EMV_PERSO_KEYS))) || exit 1; \
	echo "$$lines" | while read -r aid hex; do \
	  echo ">>> personalize $$aid ($$(( $${#hex} / 2 )) bytes)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --personalize $$aid --store-data $$hex || exit 1; \
	done

# --- eMRTD simulator ----------------------------------------------------
# Loads the common library CAP and the eMRTD CAP and creates the LDS1 instance;
# `sim-emrtd-perso` personalizes it with $(EMRTD_PERSO_SCRIPT)
# (EmrtdPersoExporter -> GPPro).
sim-emrtd-install: sim-wait card-common card-emrtd
	@for cap in $(COMMON_CAP_FILE) $(EMRTD_CAP_FILE); do \
	  echo ">>> load $$cap"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --load $$cap || exit 1; \
	done
	@awk '!/^[[:space:]]*#/ && NF >= 2 { print $$1, $$2 }' $(DEPLOY_EMRTD_CONF) | \
	while read -r instance class; do \
	  privs=""; \
	  if [ "$$instance" = "$(EMRTD_LDS1_AID)" ]; then privs="--privs $(EMRTD_LDS1_PRIVS)"; fi; \
	  echo ">>> create $$instance (applet $$class) $$privs"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --create $$instance --applet $$class \
	    --package $(EMRTD_PACKAGE_AID_HEX) $$privs || exit 1; \
	done

sim-emrtd-perso: $(HOST_STAMP)
	@lines=$$($(JAVA) -cp $(HOST_CLASSES) card42.host.emrtd.perso.EmrtdPersoExporter \
	    -script=$(abspath $(EMRTD_PERSO_SCRIPT))) || exit 1; \
	echo "$$lines" | while read -r aid hex; do \
	  echo ">>> personalize $$aid ($$(( $${#hex} / 2 )) bytes)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --personalize $$aid --store-data $$hex || exit 1; \
	done

# --- "both" simulator matrix (EMV + eMRTD coexist) --------------------------
# Loads all three CAPs and creates the instances of deploy.conf (both,
# production only); personalization is the separate `sim-perso` step.
sim-install: sim-wait card-common card-emv card-emrtd
	@for cap in $(subst $(comma), ,$(SIM_BOTH_CAPS)); do \
	  echo ">>> load $$cap"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --load $$cap || exit 1; \
	done
	@awk '!/^[[:space:]]*#/ && NF >= 2 { print $$1, $$2 }' $(DEPLOY_BOTH_CONF) | \
	while read -r instance class; do \
	  pkg=$(PACKAGE_AID_HEX); \
	  case "$$class" in $(EMRTD_PACKAGE_AID_HEX)*) pkg=$(EMRTD_PACKAGE_AID_HEX);; esac; \
	  privs=""; \
	  if [ "$$instance" = "$(EMRTD_LDS1_AID)" ]; then privs="--privs $(EMRTD_LDS1_PRIVS)"; fi; \
	  echo ">>> create $$instance (applet $$class, package $$pkg) $$privs"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --create $$instance --applet $$class \
	    --package $$pkg $$privs || exit 1; \
	done

sim-perso: $(HOST_STAMP)
	@lines=$$($(JAVA) -cp $(HOST_CLASSES) card42.host.emv.cli.Main perso export \
	    -script=$(abspath $(CARD_EMV_PERSO_SCRIPT)) -keys=$(abspath $(EMV_PERSO_KEYS))) || exit 1; \
	echo "$$lines" | while read -r aid hex; do \
	  echo ">>> personalize emv $$aid ($$(( $${#hex} / 2 )) bytes)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --personalize $$aid --store-data $$hex || exit 1; \
	done
	@lines=$$($(JAVA) -cp $(HOST_CLASSES) card42.host.emrtd.perso.EmrtdPersoExporter \
	    -script=$(abspath $(EMRTD_PERSO_SCRIPT))) || exit 1; \
	echo "$$lines" | while read -r aid hex; do \
	  echo ">>> personalize emrtd $$aid ($$(( $${#hex} / 2 )) bytes)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_SIM) --personalize $$aid --store-data $$hex || exit 1; \
	done

sim-stop:
	@if [ -f $(SIM_PID) ]; then \
	  kill $$(cat $(SIM_PID)) 2>/dev/null || true; \
	  rm -f $(SIM_PID); \
	fi
	@for pid in $$(pgrep -f "[j]csl -p=$(SIM_PORT)" 2>/dev/null || true); do \
	  echo "stopping orphaned simulator (pid $$pid)"; \
	  kill $$pid 2>/dev/null || true; \
	done
	@sleep 0.5

# --- Real card (GlobalPlatformPro) -----------------------------------------
# `*-install` LOADs the CAP(s) and CREATEs the instances (never auto-install, so
# instance AIDs match the deploy plans).  `card-install` covers both modules
# (deploy/deploy.conf, production only); `card-emv-install` / `card-emrtd-install`
# cover one module.  Personalization (STORE DATA) is the separate `*-perso` step.
# Examples:
#
#   make card-install                                # both modules
#   make card-emv-install                            # EMV (incl. test instances)
#   make card-emv-install GP_PERSONALIZE=1           # + INSTALL [for personalization]
#   make card-emv-install GP_ARGS="--key-enc ... --key-mac ..."
card-emv-install: card-common card-emv
	@for cap in $(COMMON_CAP_FILE) $(EMV_CAP_FILE); do \
	  echo ">>> load $$cap"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --load $(abspath $$cap) || exit 1; \
	done
	@awk '!/^[[:space:]]*#/ && NF >= 2 { print $$1, $$2 }' $(DEPLOY_ALL_CONF) | \
	while read -r instance class; do \
	  echo ">>> create $$instance (applet $$class)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --create $$instance --applet $$class \
	    --package $(PACKAGE_AID_HEX) || exit 1; \
	done
	@if [ "$(GP_PERSONALIZE)" = "1" ]; then \
	  awk '!/^[[:space:]]*#/ && NF >= 1 { print $$1 }' $(DEPLOY_ALL_CONF) | \
	  while read -r instance; do \
	    echo ">>> personalize $$instance"; \
	    $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --personalize $$instance || exit 1; \
	  done; \
	fi

card-emrtd-install: card-common card-emrtd
	@for cap in $(COMMON_CAP_FILE) $(EMRTD_CAP_FILE); do \
	  echo ">>> load $$cap"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --load $(abspath $$cap) || exit 1; \
	done
	@awk '!/^[[:space:]]*#/ && NF >= 2 { print $$1, $$2 }' $(DEPLOY_EMRTD_CONF) | \
	while read -r instance class; do \
	  privs=""; \
	  if [ "$$instance" = "$(EMRTD_LDS1_AID)" ]; then privs="--privs $(EMRTD_LDS1_PRIVS)"; fi; \
	  echo ">>> create $$instance (applet $$class) $$privs"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --create $$instance --applet $$class \
	    --package $(EMRTD_PACKAGE_AID_HEX) $$privs || exit 1; \
	done

card-install: card-common card-emv card-emrtd
	@for cap in $(COMMON_CAP_FILE) $(EMV_CAP_FILE) $(EMRTD_CAP_FILE); do \
	  echo ">>> load $$cap"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --load $(abspath $$cap) || exit 1; \
	done
	@awk '!/^[[:space:]]*#/ && NF >= 2 { print $$1, $$2 }' $(DEPLOY_BOTH_CONF) | \
	while read -r instance class; do \
	  pkg=$(PACKAGE_AID_HEX); \
	  case "$$class" in $(EMRTD_PACKAGE_AID_HEX)*) pkg=$(EMRTD_PACKAGE_AID_HEX);; esac; \
	  privs=""; \
	  if [ "$$instance" = "$(EMRTD_LDS1_AID)" ]; then privs="--privs $(EMRTD_LDS1_PRIVS)"; fi; \
	  echo ">>> create $$instance (applet $$class, package $$pkg) $$privs"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --create $$instance --applet $$class \
	    --package $$pkg $$privs || exit 1; \
	done

# Removes the deployed card42 applets and business packages from a card
# (destructive).  Java Card does not reclaim deleted objects on its own, so a
# clean DELETE before a re-install avoids the persistent-heap leak that repeated
# failed INSTALLs leave behind (a J3R180 then fails a later INSTALL with 6F00).
# Uses the same GP_ARGS keys as the other card targets (config/local.mk).
#
#   make card-uninstall
card-uninstall:
	@for aid in $$(awk '!/^[[:space:]]*#/ && NF >= 1 { print $$1 }' $(DEPLOY_BOTH_CONF)); do \
	  echo ">>> delete applet $$aid"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --delete $$aid || true; \
	done
	@for pkg in $(EMRTD_PACKAGE_AID_HEX) $(PACKAGE_AID_HEX); do \
	  echo ">>> delete package $$pkg"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --delete $$pkg || true; \
	done

# Personalizes every instance of $(CARD_EMV_PERSO_SCRIPT) (production set by default)
# on a real card with GPPro's `--personalize <AID> --store-data <hex>`
# (SCP02/SCP03 auto-negotiated; see docs/specs/common/toolchain.md §5 and
# docs/specs/emv/personalization.md §1).  The DGI sequences are exported by
# PersoExport and `--store-data` splits each blob and manages P1/P2, so the applet
# sees the same block sequence as the simulator path (both now driven by GPPro)
# and completion is the last block's P1.b8.  Run `make card-emv-install` first.
# Examples:
#
#   make card-emv-perso
#   make card-emv-perso GP_ARGS="--key-enc ... --key-mac ..."
#   make card-emv-perso CARD_EMV_PERSO_SCRIPT=perso/emv/sample-test.perso  # + test instances
card-emv-perso: $(HOST_STAMP)
	@lines=$$($(JAVA) -cp $(HOST_CLASSES) card42.host.emv.cli.Main perso export \
	    -script=$(abspath $(CARD_EMV_PERSO_SCRIPT)) -keys=$(abspath $(EMV_PERSO_KEYS))) || exit 1; \
	echo "$$lines" | while read -r aid hex; do \
	  echo ">>> personalize $$aid ($$(( $${#hex} / 2 )) bytes)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --personalize $$aid --store-data $$hex || exit 1; \
	done

# Personalizes the eMRTD LDS1 instance(s) of $(EMRTD_PERSO_SCRIPT) on a real card
# (same EmrtdPersoExporter -> GPPro `--store-data` path as the simulator).  Run
# `make card-emrtd-install` first.
card-emrtd-perso: $(HOST_STAMP)
	@lines=$$($(JAVA) -cp $(HOST_CLASSES) card42.host.emrtd.perso.EmrtdPersoExporter \
	    -script=$(abspath $(EMRTD_PERSO_SCRIPT))) || exit 1; \
	echo "$$lines" | while read -r aid hex; do \
	  echo ">>> personalize $$aid ($$(( $${#hex} / 2 )) bytes)"; \
	  $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --personalize $$aid --store-data $$hex || exit 1; \
	done

# Both modules, in order.
card-perso: card-emv-perso card-emrtd-perso

# Rotates the card's SCP key set with a GP PUT KEY (GPC 2.3.1 §11.8).  The keys
# currently in use come from GP_ARGS / --key-*; the new keys and key version
# from CARD_NEW_*.  DESTRUCTIVE: if the new keys are lost the card is
# irrecoverable.  Real card only (classic PC/SC transport); the simulator's
# SCP03 keys are re-injected by sim-configure on every `make sim-emv-install`.
#
#   make card-keychange GP_ARGS="--key-enc ... --key-mac ... --key-dek ..."
card-keychange:
	$(JAVA) -jar $(GP_JAR) $(GP_ARGS) \
	  --lock-enc $(CARD_NEW_ENC_KEY) --lock-mac $(CARD_NEW_MAC_KEY) \
	  --lock-dek $(CARD_NEW_DEK_KEY) --new-keyver $(CARD_NEW_KVN)

clean:
	rm -rf $(BUILD_DIR)
