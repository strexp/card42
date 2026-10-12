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

# Test build switch (docs/specs/common/architecture.md §7): 1 = allow CONTACTLESS role instances
# on the contact interface (used by the PPSE/contactless smoke test).
TEST_CONTACTLESS ?= 0

# CAP variant consumed by the deploy/test targets: debug (default) or release.
# `make` always builds both variants (release has the canonical name, debug
# carries a -debug suffix); this knob only selects which one is deployed and
# used by the test matrices.  It never appears in a target name, so the same
# targets work for both.
CAP_MODE ?= debug
