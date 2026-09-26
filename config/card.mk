# card42 real-card (GlobalPlatformPro) parameters.

GP_ARGS ?=
# Set to 1 to send INSTALL [for personalization] to every instance (GPPro).
GP_PERSONALIZE ?= 0

# eMRTD LDS1 instance: install it Default Selected with the GP CardReset
# privilege so the applet is active right after card reset and a reader can read
# EF.CardAccess at the MF level before selecting the application (Doc 9303-10
# §3.11.3, PACE discovery).  Only the LDS1 AID gets it; the LDS2 DFs do not.
# (GPPro's retired `--default` flags are not encoded for `--create`; `--privs
# CardReset` is the supported form.)
EMRTD_LDS1_AID   ?= A0000002471001
EMRTD_LDS1_PRIVS ?= CardReset

# SCP key rotation (`make card-keychange`): the new ENC/MAC/DEK keys and key
# version for the card's key set.  The keys *in use* come from GP_ARGS / --key-*.
CARD_NEW_ENC_KEY ?= 44444444444444444444444444444444
CARD_NEW_MAC_KEY ?= 55555555555555555555555555555555
CARD_NEW_DEK_KEY ?= 66666666666666666666666666666666
CARD_NEW_KVN     ?= 02
