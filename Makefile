SHELL := /bin/bash




.DEFAULT_GOAL := help

# COLORS
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)

TARGET_MAX_CHAR_NUM=20

init:
	./init.sh

ping:
	kubectl run  busyboxc1 --image=curlimages/curl --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-control-plane" }}}' -- sleep infinity
	kubectl run  busyboxc2 --image=nginx:stable-alpine3.17-slim --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-control-plane" }}}'
	kubectl run  busyboxc3 --image=nginx:stable-alpine3.17-slim --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-control-plane" }}}'
	kubectl run  busyboxw1 --image=curlimages/curl --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-worker" }}}' -- sleep infinity
	kubectl run  busyboxw2 --image=nginx:stable-alpine3.17-slim --restart=Never --overrides='{ "spec": { "nodeSelector": { "kubernetes.io/hostname": "l3cni-two-node-worker" }}}'

install_iptable_firewall:
	./iptable_firewall.sh install

uninstall_iptable_firewall:
	./iptable_firewall.sh uninstall

install_bpf_firewall:
	./bpf_firewall.sh install

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
