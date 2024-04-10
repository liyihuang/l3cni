SHELL := /bin/bash

.DEFAULT_GOAL := help

# COLORS
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=20
## Start the l3cni with no BPF and 3 pods on controller nodes 2 pods on worker nodes
init: 
	./init.sh
## Install iptable firewall
install_iptable_firewall: 
	./iptable_firewall.sh install
## Uninstall iptable firewall
uninstall_iptable_firewall: 
	./iptable_firewall.sh uninstall
## Install BPF firewall on top of the l3cni(no BPF)
install_bpf_firewall: 
	./bpf_firewall.sh install
## Initialize BPF CNI
init_bpf: #
	./init.sh bpf
## Delete the cluster
destroy: 
	kind delete cluster -n l3cni-two-node

help:
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z_0-9-]+:/{ \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "  ${YELLOW}%-$(TARGET_MAX_CHAR_NUM)s${RESET} ${GREEN}%s${RESET}\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)