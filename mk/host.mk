# card42 host artifacts: card42-common.jar (shared library), card42-emv.jar /
# card42-emrtd.jar (libraries, no CLI, so a third-party application can depend
# on them) and card42-emv-cli.jar / card42-emrtd-cli.jar (runnable CLIs).
#
# Every jar carries a Class-Path manifest entry pointing at common (the CLI
# jars also point at their library) so the five jars work from one directory.

JAR_COMMON       := $(DELIVERABLES)/card42-common.jar
JAR_EMV          := $(DELIVERABLES)/card42-emv.jar
JAR_EMRTD        := $(DELIVERABLES)/card42-emrtd.jar
JAR_EMV_CLI      := $(DELIVERABLES)/card42-emv-cli.jar
JAR_EMRTD_CLI    := $(DELIVERABLES)/card42-emrtd-cli.jar

.PHONY: jar host host-common host-emv host-emrtd host-emv-cli host-emrtd-cli

jar: host
host: host-common host-emv host-emrtd host-emv-cli host-emrtd-cli

host-common: $(JAR_COMMON)
host-emv: $(JAR_EMV)
host-emrtd: $(JAR_EMRTD)
host-emv-cli: $(JAR_EMV_CLI)
host-emrtd-cli: $(JAR_EMRTD_CLI)

$(HOST_COMMON_STAMP): $(HOST_COMMON_SRC)
	@rm -rf $(HOST_COMMON_CLASSES)
	@mkdir -p $(HOST_COMMON_CLASSES)
	$(JAVAC) -d $(HOST_COMMON_CLASSES) $(HOST_COMMON_SRC)
	@touch $@

$(JAR_COMMON): $(HOST_COMMON_STAMP)
	@mkdir -p $(dir $@)
	$(JAR) cf $@ -C $(HOST_COMMON_CLASSES) .

# EMV library (host/emv minus host/emv/cli).
$(HOST_EMV_LIB_STAMP): $(HOST_EMV_LIB_SRC) $(HOST_COMMON_STAMP)
	@rm -rf $(HOST_EMV_LIB_CLASSES)
	@mkdir -p $(HOST_EMV_LIB_CLASSES)
	$(JAVAC) -cp $(HOST_COMMON_CLASSES) -d $(HOST_EMV_LIB_CLASSES) $(HOST_EMV_LIB_SRC)
	@touch $@

$(JAR_EMV): $(HOST_EMV_LIB_STAMP)
	@mkdir -p $(dir $@)
	@printf 'Manifest-Version: 1.0\nClass-Path: card42-common.jar\n\n' \
	  > $(BUILD_DIR)/emv.mf
	$(JAR) cfm $@ $(BUILD_DIR)/emv.mf -C $(HOST_EMV_LIB_CLASSES) .

# EMV CLI (host/emv/cli), on top of the library.
$(HOST_EMV_CLI_STAMP): $(HOST_EMV_CLI_SRC) $(HOST_EMV_LIB_STAMP)
	@rm -rf $(HOST_EMV_CLI_CLASSES)
	@mkdir -p $(HOST_EMV_CLI_CLASSES)
	$(JAVAC) -cp $(HOST_COMMON_CLASSES):$(HOST_EMV_LIB_CLASSES) \
	  -d $(HOST_EMV_CLI_CLASSES) $(HOST_EMV_CLI_SRC)
	@touch $@

$(JAR_EMV_CLI): $(HOST_EMV_CLI_STAMP)
	@mkdir -p $(dir $@)
	@printf 'Manifest-Version: 1.0\nMain-Class: %s\nClass-Path: card42-common.jar card42-emv.jar\n\n' \
	  '$(MAIN_CLASS)' > $(BUILD_DIR)/emv-cli.mf
	$(JAR) cfm $@ $(BUILD_DIR)/emv-cli.mf -C $(HOST_EMV_CLI_CLASSES) .

# eMRTD library / CLI (built only once host/emrtd exists).
$(HOST_EMRTD_LIB_STAMP): $(HOST_EMRTD_LIB_SRC) $(HOST_COMMON_STAMP)
	@if [ -n "$(HOST_EMRTD_LIB_SRC)" ]; then \
	  mkdir -p $(HOST_EMRTD_LIB_CLASSES); \
	  $(JAVAC) -cp $(HOST_COMMON_CLASSES) -d $(HOST_EMRTD_LIB_CLASSES) $(HOST_EMRTD_LIB_SRC); \
	  touch $@; \
	fi

$(JAR_EMRTD): $(HOST_EMRTD_LIB_STAMP)
	@if [ -n "$(HOST_EMRTD_LIB_SRC)" ]; then \
	  mkdir -p $(dir $@); \
	  printf 'Manifest-Version: 1.0\nClass-Path: card42-common.jar\n\n' \
	    > $(BUILD_DIR)/emrtd.mf; \
	  $(JAR) cfm $@ $(BUILD_DIR)/emrtd.mf -C $(HOST_EMRTD_LIB_CLASSES) .; \
	fi

$(HOST_EMRTD_CLI_STAMP): $(HOST_EMRTD_CLI_SRC) $(HOST_EMRTD_LIB_STAMP)
	@if [ -n "$(HOST_EMRTD_CLI_SRC)" ]; then \
	  mkdir -p $(HOST_EMRTD_CLI_CLASSES); \
	  $(JAVAC) -cp $(HOST_COMMON_CLASSES):$(HOST_EMRTD_LIB_CLASSES) \
	    -d $(HOST_EMRTD_CLI_CLASSES) $(HOST_EMRTD_CLI_SRC); \
	  touch $@; \
	fi

$(JAR_EMRTD_CLI): $(HOST_EMRTD_CLI_STAMP)
	@if [ -n "$(HOST_EMRTD_CLI_SRC)" ]; then \
	  mkdir -p $(dir $@); \
	  printf 'Manifest-Version: 1.0\nMain-Class: %s\nClass-Path: card42-common.jar card42-emrtd.jar\n\n' \
	    '$(EMRTD_MAIN_CLASS)' > $(BUILD_DIR)/emrtd-cli.mf; \
	  $(JAR) cfm $@ $(BUILD_DIR)/emrtd-cli.mf -C $(HOST_EMRTD_CLI_CLASSES) .; \
	fi

# Host sources compiled together with the integration suites (also the class
# path the perso exporters run from).
$(HOST_STAMP): $(HOST_TEST_SOURCES)
	@mkdir -p $(HOST_CLASSES)
	$(JAVAC) -cp $(JC_SIM_CLIENT)/COMService/socketprovider.jar \
	  -d $(HOST_CLASSES) $(HOST_TEST_SOURCES)
	@touch $@
