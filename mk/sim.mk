# card42 Java Card simulator lifecycle (start/stop only; deployment and
# personalization are separate targets in mk/deploy.mk).

SIM_DIR ?= $(BUILD_DIR)/sim
SIM_BIN := $(SIM_DIR)/jcsl
SIM_LOG := $(SIM_DIR)/simulator.log
SIM_PID := $(SIM_DIR)/simulator.pid

.PHONY: sim-configure sim-start sim-wait sim-stop

sim-configure: sim-stop
	@mkdir -p $(SIM_DIR)
	cp $(JC_HOME_SIMULATOR)/runtime/bin/jcsl $(SIM_BIN)
	$(JAVA) -jar $(JC_HOME_SIMULATOR)/tools/Configurator.jar \
	  -binary $(SIM_BIN) -force \
	  -SCP-keyset $(SIM_KVN) $(SIM_ENC_KEY) $(SIM_MAC_KEY) $(SIM_DEK_KEY) \
	  -global-pin $(SIM_GLOBAL_PIN) $(SIM_PIN_TRIES)

sim-start: sim-configure
	@LD_LIBRARY_PATH=$(JC_HOME_SIMULATOR)/runtime/bin \
	  OPENSSL_MODULES=$(JC_HOME_SIMULATOR)/runtime/bin \
	  setsid $(SIM_BIN) -p=$(SIM_PORT) \
	  > $(SIM_LOG) 2>&1 < /dev/null & echo $$! > $(SIM_PID); \
	  echo "simulator started on port $(SIM_PORT)"

sim-wait: sim-start
	@for i in $$(seq 1 60); do \
	  grep -q "server ready on port" $(SIM_LOG) 2>/dev/null && exit 0; \
	  if grep -q "failed to bind server socket" $(SIM_LOG) 2>/dev/null; then \
	    echo "simulator could not bind port $(SIM_PORT): another jcsl may still be running"; \
	    echo "see $(SIM_LOG)"; exit 1; \
	  fi; \
	  sleep 0.5; \
	done; echo "simulator did not start, see $(SIM_LOG)"; exit 1

# Kills the tracked simulator and any orphaned jcsl still bound to the port.
sim-stop:
	@if [ -f $(SIM_PID) ]; then \
	  kill $$(cat $(SIM_PID)) 2>/dev/null || true; \
	  rm -f $(SIM_PID); \
	fi
	@for pid in $$(pgrep -f "[j]csl -p=$(SIM_PORT)" 2>/dev/null || true); do \
	  echo "stopping orphaned simulator (pid $$pid)"; \
	  kill $$pid 2>/dev/null || true; \
	done
	@sleep 0.5
