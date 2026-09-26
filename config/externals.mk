# card42 external libraries.
#
# The Java Card SDKs are auto-detected under tools/; override to point at a
# different installation.

# Java Card Development Kit Tools (converter.sh, verifyexp.sh, api_classic-*.jar).
JC_HOME_TOOLS     ?= $(firstword $(wildcard $(CURDIR)/tools/java_card_devkit_tools-bin-*))
# Java Card Development Kit Simulator (jcsl, client modules).
JC_HOME_SIMULATOR ?= $(firstword $(wildcard $(CURDIR)/tools/java_card_devkit_simulator-linux-bin-*))

# GlobalPlatform API (on-card package version 1.6, see docs/specs/common/toolchain.md).
GPAPI_DIR     ?= $(firstword $(wildcard $(CURDIR)/tools/GlobalPlatform_Card_API-*))
GPAPI_VERSION ?= 1.6

# GlobalPlatformPro.  Drives deployment/personalization on both the simulator
# (nextgen transport, config/simulator.mk) and real cards (PC/SC).
GP_JAR ?= /usr/share/java/globalplatformpro/gp.jar
