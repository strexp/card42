# card42 deployment and personalization (simulator + real card).
#
# `*-install` = LOAD the CAP(s) + CREATE the instances; personalization is the
# separate `*-perso` step.  The module keyword selects the set:
#
#   <mod> = emv    common + emv,   deploy-emv.conf + deploy-emv-test.conf
#           emrtd  common + emrtd, deploy-emrtd.conf
#           both   common + emv + emrtd, deploy.conf
#
# The CAP variant is chosen by CAP_MODE (default debug); it never appears in a
# target name.  The GPPro loops live in scripts/gp.sh, the export->STORE DATA
# pipeline in scripts/perso.sh.
#
# GP_SIM drives the simulator's nextgen transport; a real card uses the default
# PC/SC transport with GP_ARGS (config/card.mk).  The CAP is only LOADed (never
# auto-installed) so instance AIDs match the deploy plans exactly; `--create`
# cannot infer the package from the applet AID, so it is passed explicitly.

.PHONY: sim-emv-install sim-emrtd-install sim-both-install \
        sim-emv-perso sim-emrtd-perso sim-both-perso \
        card-emv-install card-emrtd-install card-both-install \
        card-emv-perso card-emrtd-perso card-both-perso \
        card-uninstall card-keychange perso-emrtd-emit

# Regenerates the AA-algorithm sample variants (perso/emrtd/sample-<aa>.perso,
# aa = sha1 | sha256 | ecdsa; EMRTD_PERSO_SCRIPT defaults to sample-sha256).
# Every sample carries all simultaneously-compatible algorithms; only AA is
# selected here.
EMRTD_AA_VARIANTS := sha1 sha256 ecdsa
perso-emrtd-emit: $(HOST_STAMP)
	@for aa in $(EMRTD_AA_VARIANTS); do \
	  echo ">>> emit sample-$$aa.perso"; \
	  $(JAVA) -cp $(abspath $(HOST_CLASSES)) card42.host.emrtd.tools.EmrtdPersoExporter \
	    -emit -aa=$$aa > perso/emrtd/sample-$$aa.perso; \
	done

# --- Simulator: install (load + create) -------------------------------------
sim-emv-install: sim-wait card
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_SIM)" \
	  $(GP_SH) load $(COMMON_CAP_SEL) $(EMV_CAP_SEL)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_SIM)" \
	  EMV_PACKAGE=$(PACKAGE_AID_HEX) \
	  $(GP_SH) create $(DEPLOY_ALL_CONF)

sim-emrtd-install: sim-wait card
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_SIM)" \
	  $(GP_SH) load $(COMMON_CAP_SEL) $(EMRTD_CAP_SEL)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_SIM)" \
	  EMV_PACKAGE=$(EMRTD_PACKAGE_AID_HEX) EMRTD_PACKAGE=$(EMRTD_PACKAGE_AID_HEX) \
	  EMRTD_AID=$(EMRTD_LDS1_AID) EMRTD_PRIVS=$(EMRTD_LDS1_PRIVS) \
	  $(GP_SH) create $(DEPLOY_EMRTD_CONF)

sim-both-install: sim-wait card
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_SIM)" \
	  $(GP_SH) load $(COMMON_CAP_SEL) $(EMV_CAP_SEL) $(EMRTD_CAP_SEL)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_SIM)" \
	  EMV_PACKAGE=$(PACKAGE_AID_HEX) EMRTD_PACKAGE=$(EMRTD_PACKAGE_AID_HEX) \
	  EMRTD_AID=$(EMRTD_LDS1_AID) EMRTD_PRIVS=$(EMRTD_LDS1_PRIVS) \
	  $(GP_SH) create $(DEPLOY_BOTH_CONF)

# --- Real card: install (load + create) -------------------------------------
# `card-emv-install GP_PERSONALIZE=1` additionally sends INSTALL [for
# personalization] to every instance.
card-emv-install: card
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_ARGS)" \
	  $(GP_SH) load $(abspath $(COMMON_CAP_SEL)) $(abspath $(EMV_CAP_SEL))
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_ARGS)" \
	  EMV_PACKAGE=$(PACKAGE_AID_HEX) \
	  $(GP_SH) create $(DEPLOY_ALL_CONF)
	@if [ "$(GP_PERSONALIZE)" = "1" ]; then \
	  awk '!/^[[:space:]]*#/ && NF >= 1 { print $$1 }' $(DEPLOY_ALL_CONF) | \
	  while read -r instance; do \
	    echo ">>> personalize $$instance"; \
	    $(JAVA) -jar $(GP_JAR) $(GP_ARGS) --personalize $$instance || exit 1; \
	  done; \
	fi

card-emrtd-install: card
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_ARGS)" \
	  $(GP_SH) load $(abspath $(COMMON_CAP_SEL)) $(abspath $(EMRTD_CAP_SEL))
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_ARGS)" \
	  EMV_PACKAGE=$(EMRTD_PACKAGE_AID_HEX) EMRTD_PACKAGE=$(EMRTD_PACKAGE_AID_HEX) \
	  EMRTD_AID=$(EMRTD_LDS1_AID) EMRTD_PRIVS=$(EMRTD_LDS1_PRIVS) \
	  $(GP_SH) create $(DEPLOY_EMRTD_CONF)

card-both-install: card
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_ARGS)" \
	  $(GP_SH) load $(abspath $(COMMON_CAP_SEL)) $(abspath $(EMV_CAP_SEL)) \
	    $(abspath $(EMRTD_CAP_SEL))
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_ARGS)" \
	  EMV_PACKAGE=$(PACKAGE_AID_HEX) EMRTD_PACKAGE=$(EMRTD_PACKAGE_AID_HEX) \
	  EMRTD_AID=$(EMRTD_LDS1_AID) EMRTD_PRIVS=$(EMRTD_LDS1_PRIVS) \
	  $(GP_SH) create $(DEPLOY_BOTH_CONF)

# --- Personalization (STORE DATA) -------------------------------------------
# The EMV exporter is the CLI's `perso export`; the eMRTD exporter is
# EmrtdPersoExporter.  Both print "aid hex" lines consumed by scripts/perso.sh.
sim-emv-perso: $(HOST_STAMP)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_SH="$(GP_SH)" GP_TRANSPORT="$(GP_SIM)" \
	  $(PERSO_SH) $(JAVA) -cp $(HOST_CLASSES) card42.host.emv.cli.Main perso export \
	    -script=$(abspath $(SIM_EMV_PERSO_SCRIPT)) -keys=$(abspath $(EMV_PERSO_KEYS))

sim-emrtd-perso: $(HOST_STAMP)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_SH="$(GP_SH)" GP_TRANSPORT="$(GP_SIM)" \
	  $(PERSO_SH) $(JAVA) -cp $(HOST_CLASSES) card42.host.emrtd.tools.EmrtdPersoExporter \
	    -script=$(abspath $(EMRTD_PERSO_SCRIPT))

sim-both-perso: $(HOST_STAMP)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_SH="$(GP_SH)" GP_TRANSPORT="$(GP_SIM)" \
	  $(PERSO_SH) $(JAVA) -cp $(HOST_CLASSES) card42.host.emv.cli.Main perso export \
	    -script=$(abspath $(SIM_BOTH_EMV_PERSO_SCRIPT)) -keys=$(abspath $(EMV_PERSO_KEYS))
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_SH="$(GP_SH)" GP_TRANSPORT="$(GP_SIM)" \
	  $(PERSO_SH) $(JAVA) -cp $(HOST_CLASSES) card42.host.emrtd.tools.EmrtdPersoExporter \
	    -script=$(abspath $(EMRTD_PERSO_SCRIPT))

card-emv-perso: $(HOST_STAMP)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_SH="$(GP_SH)" GP_TRANSPORT="$(GP_ARGS)" \
	  $(PERSO_SH) $(JAVA) -cp $(HOST_CLASSES) card42.host.emv.cli.Main perso export \
	    -script=$(abspath $(CARD_EMV_PERSO_SCRIPT)) -keys=$(abspath $(EMV_PERSO_KEYS))

card-emrtd-perso: $(HOST_STAMP)
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_SH="$(GP_SH)" GP_TRANSPORT="$(GP_ARGS)" \
	  $(PERSO_SH) $(JAVA) -cp $(HOST_CLASSES) card42.host.emrtd.tools.EmrtdPersoExporter \
	    -script=$(abspath $(EMRTD_PERSO_SCRIPT))

card-both-perso: card-emv-perso card-emrtd-perso

# --- Card housekeeping ------------------------------------------------------
# Removes the deployed applets and business packages (destructive).  Java Card
# does not reclaim deleted objects on its own, so a clean DELETE before a
# re-install avoids the persistent-heap leak that repeated failed INSTALLs leave
# behind (a J3R180 then fails a later INSTALL with 6F00).  The common library
# package is deleted last, after its EMV/eMRTD clients, so a re-LOAD of
# common.cap does not fail with 6985.
card-uninstall:
	@GP_JAVA="$(JAVA)" GP_JAR="$(GP_JAR)" GP_TRANSPORT="$(GP_ARGS)" GP_FORCE="-f" \
	  $(GP_SH) delete $(DEPLOY_BOTH_CONF) $(EMRTD_PACKAGE_AID_HEX) \
	    $(PACKAGE_AID_HEX) $(COMMON_PACKAGE_AID_HEX)

# Rotates the card's SCP key set with a GP PUT KEY (GPC 2.3.1 §11.8).  The keys
# currently in use come from GP_ARGS / --key-*; the new keys and key version
# from CARD_NEW_*.  DESTRUCTIVE: if the new keys are lost the card is
# irrecoverable.  Real card only (classic PC/SC); the simulator's SCP03 keys
# are re-injected by sim-configure on every sim install.
card-keychange:
	$(JAVA) -jar $(GP_JAR) $(GP_ARGS) \
	  --lock-enc $(CARD_NEW_ENC_KEY) --lock-mac $(CARD_NEW_MAC_KEY) \
	  --lock-dek $(CARD_NEW_DEK_KEY) --new-keyver $(CARD_NEW_KVN)
