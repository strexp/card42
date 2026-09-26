# card42 build layout and switches.
#
# Included by the top-level Makefile; see README.md "Configuration".
# Every value uses ?= so the command line, the environment and config/local.mk
# take precedence over these defaults.

# Output directory (build artefacts, generated sources, simulator state).
BUILD_DIR ?= build

# Card-side source trees.  card/common is built as the
# card42common library CAP; card/emv and card/emrtd are the business CAPs that
# depend on it.
CARD_COMMON_DIR ?= card/common
CARD_EMV_DIR    ?= card/emv
CARD_EMRTD_DIR  ?= card/emrtd

# Backward-compatible alias used by the EMV test wiring.
CARD_DIR ?= $(CARD_EMV_DIR)

# Test build switch (docs/specs/common/architecture.md §7): 1 = allow CONTACTLESS role instances
# on the contact interface (used by the PPSE/contactless smoke test).
TEST_CONTACTLESS ?= 0
