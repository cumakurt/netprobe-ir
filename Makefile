.PHONY: build test integration integration-tls install uninstall clean

build:
	./scripts/build-static.sh

test:
	./scripts/test-all.sh

integration: build
	./scripts/integration-live-linux.sh

integration-tls: build
	./scripts/integration-live-tls-linux.sh

install: build
	./install.sh

uninstall:
	./uninstall.sh

clean:
	rm -rf dist/*
