.PHONY: test appliance appliance-rootfs appliance-raw appliance-qcow2 appliance-vdi appliance-vmdk appliance-ova appliance-formats takeaway-linux test-appliance prune-cache clean-cache clean-appliance clean-takeaway

PYTHON ?= .venv/bin/python
APPLIANCE_NAME ?= saslik-amd64
APPLIANCE_DIST ?= dist
APPLIANCE_BUILD ?= build/appliance
APPLIANCE_CACHE ?= build/cache/appliance
BUILD_TMP ?= $(APPLIANCE_BUILD)/tmp
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
TAKEAWAY_NAME ?= saslik-takeaway-linux-amd64
TAKEAWAY_SOURCE_DATA ?= $(HOME)/.local/share/saslik
TAKEAWAY_OUTPUT ?= $(APPLIANCE_DIST)/$(TAKEAWAY_NAME).tar.gz

test:
	$(PYTHON) -m compileall -q src
	$(PYTHON) -m unittest discover -s tests -v
	bash -n scripts/test-appliance-qemu.sh
	bash -n scripts/build-appliance-rootfs.sh
	bash -n scripts/build-appliance-disk.sh
	bash -n scripts/prepare-appliance-raw.sh
	bash -n scripts/export-appliance.sh
	bash -n scripts/build-takeaway-linux.sh
	bash -n scripts/takeaway/saslik

# The raw disk is the canonical, hypervisor-neutral appliance artifact.
# APPLIANCE_RAW_SOURCE optionally imports an existing bootable disk instead
# of provisioning Ubuntu; it may itself be raw or qcow2.
appliance: appliance-qcow2

appliance-rootfs: $(APPLIANCE_ROOTFS_STAMP)

$(APPLIANCE_ROOTFS_STAMP):
	mkdir -p "$(BUILD_TMP)"
	sudo env TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/build-appliance-rootfs.sh \
		--suite "$(APPLIANCE_UBUNTU_SUITE)" \
		--mirror "$(APPLIANCE_UBUNTU_MIRROR)" \
		--source "$(CURDIR)" \
		--cache "$(APPLIANCE_CACHE)" \
		--output "$(APPLIANCE_ROOTFS)"

appliance-raw: $(APPLIANCE_RAW)

ifeq ($(strip $(APPLIANCE_RAW_SOURCE)),)
$(APPLIANCE_RAW): $(APPLIANCE_ROOTFS_STAMP)
	mkdir -p "$(BUILD_TMP)"
	sudo env TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/build-appliance-disk.sh \
		--rootfs "$(APPLIANCE_ROOTFS)" \
		--output "$(APPLIANCE_RAW)" \
		--size "$(APPLIANCE_DISK_SIZE)"
else
$(APPLIANCE_RAW):
	mkdir -p "$(BUILD_TMP)"
	TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/prepare-appliance-raw.sh "$(APPLIANCE_RAW_SOURCE)" "$(APPLIANCE_RAW)"
endif

appliance-qcow2: $(APPLIANCE_RAW)
	mkdir -p "$(BUILD_TMP)"
	TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/export-appliance.sh qcow2 "$(APPLIANCE_RAW)" "$(APPLIANCE_QCOW2)"

appliance-vdi: $(APPLIANCE_RAW)
	mkdir -p "$(BUILD_TMP)"
	TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/export-appliance.sh vdi "$(APPLIANCE_RAW)" "$(APPLIANCE_VDI)"

appliance-vmdk: $(APPLIANCE_RAW)
	mkdir -p "$(BUILD_TMP)"
	TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/export-appliance.sh vmdk "$(APPLIANCE_RAW)" "$(APPLIANCE_VMDK)"

appliance-ova: $(APPLIANCE_RAW)
	mkdir -p "$(BUILD_TMP)"
	TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/export-appliance.sh ova "$(APPLIANCE_RAW)" "$(APPLIANCE_OVA)"

appliance-formats: appliance-qcow2 appliance-vdi appliance-ova

takeaway-linux: $(APPLIANCE_ROOTFS_STAMP)
	mkdir -p "$(BUILD_TMP)"
	sudo env TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/build-takeaway-linux.sh \
		--rootfs "$(APPLIANCE_ROOTFS)" \
		--source-data "$(TAKEAWAY_SOURCE_DATA)" \
		--source "$(CURDIR)" \
		--work-root "$(abspath $(BUILD_TMP))/takeaway" \
		--name "$(TAKEAWAY_NAME)" \
		--output "$(TAKEAWAY_OUTPUT)"

test-appliance:
	mkdir -p "$(BUILD_TMP)"
	TMPDIR="$(abspath $(BUILD_TMP))" ./scripts/test-appliance-qemu.sh $(APPLIANCE_IMAGE)

prune-cache:
	PYTHONPATH=src $(PYTHON) -m saslik.build_cache prune --cache "$(APPLIANCE_CACHE)"

clean-cache:
	PYTHONPATH=src $(PYTHON) -m saslik.build_cache clean --cache "$(APPLIANCE_CACHE)"

clean-appliance:
	rm -f -- "$(APPLIANCE_RAW)" "$(APPLIANCE_QCOW2)" "$(APPLIANCE_VDI)" "$(APPLIANCE_VMDK)" "$(APPLIANCE_OVA)"

clean-takeaway:
	rm -f -- "$(TAKEAWAY_OUTPUT)"
