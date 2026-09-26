# card42 Java Card package and applet IDs.
#
# All class AIDs derive from the shared card42 RID; the PSE / PPSE directory
# instance AIDs are the standard EMV alias names (different RID) and are chosen
# at INSTALL time, not declared in a CAP.

# "CARDB" (private RID; replace before production)
CARD42_RID ?= 0x43:0x41:0x52:0x44:0x42

# --- card42common library package (no applet) --------------------------------
COMMON_PACKAGE_NAME ?= card42.common
COMMON_PACKAGE_AID  ?= $(CARD42_RID):0x00
COMMON_VERSION      ?= 1.0

# --- card42-emv package ------------------------------------------------------
PACKAGE_NAME    ?= card42.emv
PACKAGE_AID     ?= $(CARD42_RID):0x01
PACKAGE_VERSION ?= 1.0
APPLET_CLASS    ?= card42.emv.PaymentApplet
APPLET_AID      ?= $(CARD42_RID):0x01:0x01
DIRECTORY_CLASS ?= card42.emv.DirectoryApplet
DIRECTORY_AID   ?= $(CARD42_RID):0x01:0x03

# --- card42-emrtd package --------------------------------------------------
EMRTD_PACKAGE_NAME ?= card42.emrtd
EMRTD_PACKAGE_AID  ?= $(CARD42_RID):0x02
EMRTD_CLASS        ?= card42.emrtd.EmrtdApplet
EMRTD_AID          ?= $(CARD42_RID):0x02:0x01
