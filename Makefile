# card42 - Java Card applet (CAP) + host reference stack (jar) build
#
# Overridable configuration (examples):
#   make JAVA_HOME=/path/to/jdk        (must be a full JDK, i.e. contain bin/javac)
#   make JC_HOME_TOOLS=/opt/jc-tools JC_HOME_SIMULATOR=/opt/jc-sim
#   make JC_TARGET=3.1.0 JC_API_VERSION=3.1.0
#   make TEST_CONTACTLESS=1            (test build, docs/specs/common/architecture.md §7)
#   make CAP_MODE=release test-emv-sim (deploy/test the release CAPs instead of debug)
#
# The tunable defaults live in config/*.mk (one file per category); copy
# config/local.mk.example to config/local.mk for persistent local overrides.
# Command-line assignments and the environment always win over both.
#
# The build rules live under mk/ (one file per category); see
# docs/specs/common/toolchain.md for the full target list.

# The included fragments define targets before `all` below, so pin the goal.
.DEFAULT_GOAL := all

# --- Configuration ----------------------------------------------------------
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

# --- Build rules (one file per category) ------------------------------------
include mk/paths.mk
include mk/cap.mk
include mk/host.mk
include mk/sim.mk
include mk/deploy.mk
include mk/test.mk
include mk/unit.mk

# --- Aggregates -------------------------------------------------------------
.PHONY: all help clean

all: card jar

# `make` builds both CAP variants (release + debug) and the five host jars;
# CAP_MODE only picks which CAP variant the deploy/test targets consume.
help:
	@echo 'card42 build targets:'
	@echo '  make [card]               build debug + release CAPs and the five host jars'
	@echo '  make verify               verify every export file (.exp)'
	@echo '  make clean                remove $(BUILD_DIR)'
	@echo '  make test-unit            pure-JVM unit tests (no simulator)'
	@echo '  make test-unit-<mod>      module unit tests, <mod> = common | emv | emrtd'
	@echo '  make test-<mod>-sim       simulator integration suites, <mod> = emv | emrtd | both'
	@echo '  make test-<mod>-card      real-card integration suites'
	@echo '  make sim-<mod>-install    simulator: load CAPs + create instances'
	@echo '  make sim-<mod>-perso      simulator: store the personalization data'
	@echo '  make card-<mod>-install   real card: load CAPs + create instances'
	@echo '  make card-<mod>-perso     real card: store the personalization data'
	@echo '  make CAP_MODE=release ... deploy/test the release CAPs (default: debug)'

clean:
	rm -rf $(BUILD_DIR)
