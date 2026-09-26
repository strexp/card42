# card42 simulator parameters.
#
# The SCP03 keyset and global PIN below are test-only defaults; put real values
# in config/local.mk (gitignored) instead of committing them.

SIM_PORT       ?= 9025
SIM_KVN        ?= 01
SIM_ENC_KEY    ?= 11111111111111111111111111111111
SIM_MAC_KEY    ?= 22222222222222222222222222222222
SIM_DEK_KEY    ?= 33333333333333333333333333333333
SIM_GLOBAL_PIN ?= 000000000000
SIM_PIN_TRIES  ?= 03

# Deployment plans (read by the GPPro deploy loops in the Makefile):
#   deploy-emv.conf      EMV production instances
#   deploy-emv-test.conf EMV test-only instances (appended for simulator/card tests)
#   deploy-emrtd.conf    eMRTD LDS1 instance
#   deploy.conf          both (EMV + eMRTD)
DEPLOY_CONF          ?= deploy/deploy-emv.conf
DEPLOY_EMV_TEST_CONF ?= deploy/deploy-emv-test.conf
DEPLOY_EMRTD_CONF    ?= deploy/deploy-emrtd.conf
DEPLOY_BOTH_CONF     ?= deploy/deploy.conf

# CAPs to deploy, in load order; comma separated.  The card42common library CAP
# must be LOADed before the business CAP that imports it.
SIM_CAPS      ?= $(COMMON_CAP_FILE),$(EMV_CAP_FILE)
SIM_BOTH_CAPS ?= $(COMMON_CAP_FILE),$(EMV_CAP_FILE),$(EMRTD_CAP_FILE)

# GPPro invocation for the simulator: the nextgen transport over the jcsl JCSDK
# socket.  This is the only GPPro transport that speaks the simulator protocol,
# and it is marked experimental upstream, so it is confined to the simulator
# (see docs/specs/common/toolchain.md §4).  Real cards use the default PC/SC transport
# with GP_ARGS (config/card.mk), never --ng.
GP_SIM ?= --ng --simulator localhost:$(SIM_PORT) \
          --key-enc $(SIM_ENC_KEY) --key-mac $(SIM_MAC_KEY) --key-dek $(SIM_DEK_KEY) \
          --key-ver $(SIM_KVN)
