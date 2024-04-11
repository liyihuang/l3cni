SHELL := /bin/bash


.DEFAULT_GOAL := help

# COLORS
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=20
## Start kind cluster with 2 nodes and use l3cni as the CNI(no BPF), schedule 3 pods(c1,c2,c3) on controller nodes, 2 pods(w1,w2) on worker nodes(c1 is curl client, c2 and c3 are nginx servers, w1 is curl client and w2 is nginx server)
init: 
	./init.sh
## Install iptable firewall on top of the l3cni(no BPF) to block the traffic from c1 to c2
install_iptable_firewall: 
	./iptable_firewall.sh install
## Uninstall iptable firewall on top of the l3cni(no BPF) to unblock the iptable rule from c1 to c2
uninstall_iptable_firewall: 
	./iptable_firewall.sh uninstall
## Install BPF firewall on top of the l3cni(no BPF forwarding) to block the traffic from c1 to c2
install_bpf_firewall: 
	./bpf_firewall.sh install

## Uninstall BPF firewall on top of the l3cni(no BPF forwarding)
uninstall_bpf_firewall: 
	./bpf_firewall.sh uninstall
## Start kind cluster with 2 nodes and use l3cni_bpf as the CNI(no proxy ARP or routing on kernel, just BPF do forwarding) (c1 can talk to c2 and c3 but can't talk to w1 or w2)
init_l3cni_bpf:
	./init.sh bpf

## Update the bpf map for l3cni_bpf so the pods on the different nodes can ping  (c1 can talk to c2, c3, w1 and w2)
update_inter_node_bpf_map: #
	./bpf_inter_node.sh
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