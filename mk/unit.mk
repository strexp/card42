# card42 pure-JVM unit tests (no simulator required).
#
# The card-side classes are linked against the minimal javacard.framework stubs
# in test/common/stubs (placed before the API jar) and the host-side classes
# run directly.  All suites share package card42.test, so they are collected
# recursively.  Shared unit support and the runner live in test/common/unit;
# EMV and eMRTD suite lists live with their own tests (EmvSuites/EmrtdSuites).
#
# UNIT_CARD_SRC is an explicit list on purpose: the stubs are deliberately
# minimal, and the applet entry/base classes plus the command and RSA/key
# classes (APDU output, KeyBuilder.TYPE_RSA_CRT_PRIVATE, Signature) only
# compile against the full Java Card API used by the CAP build.  A plain
# `find card` glob fails with ~32 javac errors, so the compilable subset is
# listed here, grouped by module and package.

.PHONY: test-unit test-unit-common test-unit-emv test-unit-emrtd

UNIT_DIR      := $(BUILD_DIR)/unit
UNIT_STUBS    := $(UNIT_DIR)/stubs
UNIT_CLASSES  := $(UNIT_DIR)/classes
UNIT_STUB_STAMP  := $(UNIT_STUBS)/.compiled
UNIT_CLASS_STAMP := $(UNIT_CLASSES)/.compiled

UNIT_STUB_SRC := $(wildcard test/common/stubs/javacard/framework/*.java) \
                 $(wildcard test/common/stubs/javacard/security/*.java) \
                 $(wildcard test/common/stubs/javacardx/crypto/*.java)
UNIT_SRC      := $(shell find test/emv/unit -name '*.java') \
                 $(shell find test/emrtd/unit -name '*.java') \
                 $(shell find test/common -name '*.java')

UNIT_CARD_SRC := \
  $(CARD_COMMON_DIR)/applet/ApduIo.java $(CARD_COMMON_DIR)/applet/AppletBase.java \
  $(CARD_COMMON_DIR)/applet/InstallParams.java $(CARD_COMMON_DIR)/applet/IsoStatus.java \
  $(CARD_COMMON_DIR)/applet/PersoErrors.java \
  $(CARD_COMMON_DIR)/crypto/AesCmac.java $(CARD_COMMON_DIR)/crypto/ConstantTime.java \
  $(CARD_COMMON_DIR)/crypto/MacAlgorithm.java $(CARD_COMMON_DIR)/crypto/RetailMac.java \
  $(CARD_COMMON_DIR)/mem/TransientBuffers.java \
  $(CARD_COMMON_DIR)/tlv/Iso7816Padding.java $(CARD_COMMON_DIR)/tlv/Tlv.java \
  $(CARD_COMMON_DIR)/tlv/TlvReader.java \
  \
  $(CARD_EMV_DIR)/applet/InstallParameters.java \
  $(CARD_EMV_DIR)/builder/AcResponseBuilder.java $(CARD_EMV_DIR)/builder/DirectoryBuilder.java \
  $(CARD_EMV_DIR)/builder/FciBuilder.java $(CARD_EMV_DIR)/builder/RecordBuilder.java \
  $(CARD_EMV_DIR)/crypto/Arpc.java \
  $(CARD_EMV_DIR)/constants/Defaults.java $(CARD_EMV_DIR)/constants/EMVCodes.java \
  $(CARD_EMV_DIR)/constants/EMVCommands.java $(CARD_EMV_DIR)/constants/EMVRoles.java \
  $(CARD_EMV_DIR)/constants/EMVStatus.java \
  $(CARD_EMV_DIR)/crypto/CryptoProfile.java $(CARD_EMV_DIR)/crypto/EMVCrypto.java \
  $(CARD_EMV_DIR)/sm/SecureMessaging.java $(CARD_EMV_DIR)/crypto/SessionKey.java \
  $(CARD_EMV_DIR)/data/DirectoryRecords.java $(CARD_EMV_DIR)/data/EMVStaticData.java \
  $(CARD_EMV_DIR)/data/Iad.java $(CARD_EMV_DIR)/data/PaymentData.java \
  $(CARD_EMV_DIR)/data/RecordStore.java $(CARD_EMV_DIR)/data/SdaCertificateData.java \
  $(CARD_EMV_DIR)/data/TransactionLog.java \
  $(CARD_EMV_DIR)/mem/EmvEngines.java $(CARD_EMV_DIR)/mem/EmvScratch.java \
  $(CARD_EMV_DIR)/perso/PersoRules.java \
  $(CARD_EMV_DIR)/risk/CardRiskManagement.java $(CARD_EMV_DIR)/risk/OfflineRisk.java \
  $(CARD_EMV_DIR)/state/EMVProtocolState.java \
  $(CARD_EMV_DIR)/tlv/Dgi.java $(CARD_EMV_DIR)/tlv/DgiReader.java \
  $(CARD_EMV_DIR)/tlv/DolReader.java $(CARD_EMV_DIR)/constants/TlvTags.java \
  \
  $(CARD_EMRTD_DIR)/access/AbstractSecureMessaging.java $(CARD_EMRTD_DIR)/access/BacCrypto.java \
  $(CARD_EMRTD_DIR)/access/ChipAuth.java $(CARD_EMRTD_DIR)/access/Iso7816Sm.java \
  $(CARD_EMRTD_DIR)/access/Iso7816SmAes.java \
  $(CARD_EMRTD_DIR)/access/PaceSeedSink.java $(CARD_EMRTD_DIR)/access/SecureMessaging.java \
  $(CARD_EMRTD_DIR)/applet/EmrtdApplet.java $(CARD_EMRTD_DIR)/applet/EmrtdInstallParameters.java \
  $(CARD_EMRTD_DIR)/command/lds1/ExternalAuthenticate.java $(CARD_EMRTD_DIR)/command/lds1/GetChallenge.java \
  $(CARD_EMRTD_DIR)/command/lds1/InternalAuthenticate.java $(CARD_EMRTD_DIR)/command/lds2/Lds2File.java \
  $(CARD_EMRTD_DIR)/command/lds2/Lds2Record.java $(CARD_EMRTD_DIR)/command/lds1/Mse.java \
  $(CARD_EMRTD_DIR)/command/lds1/PsoVerifyCertificate.java $(CARD_EMRTD_DIR)/command/lds1/ReadBinary.java \
  $(CARD_EMRTD_DIR)/command/lds1/SelectFile.java \
  $(CARD_EMRTD_DIR)/crypto/AaCrypto.java $(CARD_EMRTD_DIR)/crypto/P256.java \
  $(CARD_EMRTD_DIR)/crypto/Sha1Kdf.java \
  $(CARD_EMRTD_DIR)/lds/lds2/Lds2FileSystem.java $(CARD_EMRTD_DIR)/lds/lds2/Lds2RecordFile.java \
  $(CARD_EMRTD_DIR)/lds/common/PagedFile.java \
  $(CARD_EMRTD_DIR)/lds/lds2/Lds2TransparentFile.java $(CARD_EMRTD_DIR)/lds/lds1/LdsCatalog.java \
  $(CARD_EMRTD_DIR)/lds/lds1/LdsFile.java $(CARD_EMRTD_DIR)/lds/lds1/LdsFileSystem.java \
  $(CARD_EMRTD_DIR)/lds/common/LdsMfStore.java \
  $(CARD_EMRTD_DIR)/mem/EmrtdScratch.java $(CARD_EMRTD_DIR)/mem/KdfEngines.java \
  $(CARD_EMRTD_DIR)/mem/MacEngines.java $(CARD_EMRTD_DIR)/mem/SmScratch.java \
  $(CARD_EMRTD_DIR)/perso/common/DgiStream.java $(CARD_EMRTD_DIR)/perso/lds2/Lds2Perso.java \
  $(CARD_EMRTD_DIR)/perso/lds1/LdsPerso.java \
  $(CARD_EMRTD_DIR)/ta/TaContext.java \
  $(CARD_EMRTD_DIR)/ta/TaKeys.java $(CARD_EMRTD_DIR)/ta/TaTrustStore.java \
  $(CARD_EMRTD_DIR)/constants/EmrtdTags.java

UNIT_HOST_SRC := $(HOST_COMMON_SRC) $(HOST_EMV_SRC) $(HOST_EMRTD_SRC)

# The applet implements org.globalplatform.Personalization (GP API 1.6), so the
# GP API jar links the command-level card tests in the pure-JVM unit build.
GPAPI_JAR := $(GPAPI)/gpapi-globalplatform.jar
UNIT_CP   := $(UNIT_CLASSES):$(UNIT_STUBS):$(JC_TOOLS_LIB)/api_classic-$(JC_API_VERSION).jar:$(GPAPI_JAR)

$(UNIT_STUB_STAMP): $(UNIT_STUB_SRC)
	@mkdir -p $(UNIT_STUBS)
	$(JAVAC) -d $(UNIT_STUBS) $(UNIT_STUB_SRC)
	@touch $@

$(UNIT_CLASS_STAMP): $(UNIT_STUB_STAMP) $(UNIT_CARD_SRC) $(UNIT_HOST_SRC) $(UNIT_SRC)
	@mkdir -p $(UNIT_CLASSES)
	$(JAVAC) -d $(UNIT_CLASSES) \
	  -cp $(UNIT_STUBS):$(JC_TOOLS_LIB)/api_classic-$(JC_API_VERSION).jar:$(GPAPI_JAR) \
	  $(UNIT_CARD_SRC) $(UNIT_HOST_SRC) $(UNIT_SRC)
	@touch $@

UNIT_RUN := $(JAVA) -cp $(UNIT_CP) card42.test.UnitTests

test-unit: $(UNIT_CLASS_STAMP)
	$(UNIT_RUN)

# Module-scoped runs: common guards plus the selected module's suites.
test-unit-common: $(UNIT_CLASS_STAMP)
	$(UNIT_RUN) common

test-unit-emv: $(UNIT_CLASS_STAMP)
	$(UNIT_RUN) emv

test-unit-emrtd: $(UNIT_CLASS_STAMP)
	$(UNIT_RUN) emrtd
