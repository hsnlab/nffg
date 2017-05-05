.DEFAULT_GOAL := init

all: init install

init:
	sudo apt update && sudo apt install -y python-pip && sudo -H pip install networkx

dev:
	sudo python setup.py develop

install:
	sudo python setup.py install

clean:
	sudo python setup.py develop --uninstall
	sudo rm -rf /usr/local/bin/nffg_diff.py

.PHONY: all init dev install clean
