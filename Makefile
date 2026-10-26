.PHONY: test appliance appliance-rootfs appliance-raw appliance-qcow2 appliance-vdi appliance-vmdk appliance-ova appliance-formats test-appliance clean-appliance

PYTHON ?= .venv/bin/python
APPLIANCE_NAME ?= saslik-amd64
APPLIANCE_DIST ?= dist
APPLIANCE_BUILD ?= build/appliance
APPLIANCE_ROOTFS ?= $(APPLIANCE_BUILD)/rootfs
APPLIANCE_ROOTFS_STAMP ?= $(APPLIANCE_ROOTFS)/usr/share/saslik/build-info
APPLIANCE_UBUNTU_SUITE ?= resolute
APPLIANCE_UBUNTU_MIRROR ?= http://archive.ubuntu.com/ubuntu
APPLIANCE_DISK_SIZE ?= 16G
APPLIANCE_RAW ?= $(APPLIANCE_DIST)/$(APPLIANCE_NAME).raw
APPLIANCE_RAW_SOURCE ?=
APPLIANCE_QCOW2 ?= $(APPLIANCE_DIST)/$(APPLIANCE_NAME).qcow2
APPLIANCE_VDI ?= $(APPLIANCE_DIST)/$(APPLIANCE_NAME).vdi
APPLIANCE_VMDK ?= $(APPLIANCE_DIST)/$(APPLIANCE_NAME).vmdk
APPLIANCE_OVA ?= $(APPLIANCE_DIST)/$(APPLIANCE_NAME).ova
APPLIANCE_IMAGE ?= $(APPLIANCE_QCOW2)

test:
	$(PYTHON) -m compileall -q src
	$(PYTHON) -m unittest discover -s tests -v
	bash -n scripts/test-appliance-qemu.sh
	bash -n scripts/build-appliance-rootfs.sh
	bash -n scripts/build-appliance-disk.sh
	bash -n scripts/prepare-appliance-raw.sh
	bash -n scripts/export-appliance.sh

# The raw disk is the canonical, hypervisor-neutral appliance artifact.
# APPLIANCE_RAW_SOURCE optionally imports an existing bootable disk instead
# of provisioning Ubuntu; it may itself be raw or qcow2.
appliance: appliance-qcow2

appliance-rootfs: $(APPLIANCE_ROOTFS_STAMP)

$(APPLIANCE_ROOTFS_STAMP):
	sudo ./scripts/build-appliance-rootfs.sh \
		--suite "$(APPLIANCE_UBUNTU_SUITE)" \
		--mirror "$(APPLIANCE_UBUNTU_MIRROR)" \
		--source "$(CURDIR)" \
		--output "$(APPLIANCE_ROOTFS)"

appliance-raw: $(APPLIANCE_RAW)

ifeq ($(strip $(APPLIANCE_RAW_SOURCE)),)
$(APPLIANCE_RAW): $(APPLIANCE_ROOTFS_STAMP)
	sudo ./scripts/build-appliance-disk.sh \
		--rootfs "$(APPLIANCE_ROOTFS)" \
		--output "$(APPLIANCE_RAW)" \
		--size "$(APPLIANCE_DISK_SIZE)"
else
$(APPLIANCE_RAW):
	./scripts/prepare-appliance-raw.sh "$(APPLIANCE_RAW_SOURCE)" "$(APPLIANCE_RAW)"
endif

appliance-qcow2: $(APPLIANCE_RAW)
	./scripts/export-appliance.sh qcow2 "$(APPLIANCE_RAW)" "$(APPLIANCE_QCOW2)"

appliance-vdi: $(APPLIANCE_RAW)
	./scripts/export-appliance.sh vdi "$(APPLIANCE_RAW)" "$(APPLIANCE_VDI)"

appliance-vmdk: $(APPLIANCE_RAW)
	./scripts/export-appliance.sh vmdk "$(APPLIANCE_RAW)" "$(APPLIANCE_VMDK)"

appliance-ova: $(APPLIANCE_RAW)
	./scripts/export-appliance.sh ova "$(APPLIANCE_RAW)" "$(APPLIANCE_OVA)"

appliance-formats: appliance-qcow2 appliance-vdi appliance-ova

test-appliance:
	./scripts/test-appliance-qemu.sh $(APPLIANCE_IMAGE)

clean-appliance:
	rm -f -- "$(APPLIANCE_RAW)" "$(APPLIANCE_QCOW2)" "$(APPLIANCE_VDI)" "$(APPLIANCE_VMDK)" "$(APPLIANCE_OVA)"
