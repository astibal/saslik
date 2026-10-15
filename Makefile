.PHONY: test test-appliance

PYTHON ?= .venv/bin/python
APPLIANCE_IMAGE ?= dist/saslik-amd64.qcow2

test:
	$(PYTHON) -m compileall -q src
	$(PYTHON) -m unittest discover -s tests -v
	bash -n scripts/test-appliance-qemu.sh

test-appliance:
	./scripts/test-appliance-qemu.sh $(APPLIANCE_IMAGE)
