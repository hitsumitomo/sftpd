SFTP_BIN=bin/sftpd
SFTP_INSTALL=/usr/local/bin/sftpd

SEED ?=
SEED1 ?=
SEED2 ?=

build:
	@echo "Building..."
	@go mod tidy
	@if [ -n "$(SEED)" ]; then \
		if [ "$(SEED)" = "random" ]; then \
			SEED1_VAL=$$(od -An -N8 -tu8 < /dev/urandom | tr -d ' '); \
			SEED2_VAL=$$(od -An -N8 -tu8 < /dev/urandom | tr -d ' '); \
		else \
			_hash=$$(echo -n "$(SEED)" | sha256sum | awk '{print $$1}'); \
			SEED1_VAL=0x$$(echo "$$_hash" | head -c 16); \
			SEED2_VAL=0x$$(echo "$$_hash" | cut -c 17-32); \
		fi; \
		echo "Generated SEED1=$$SEED1_VAL SEED2=$$SEED2_VAL"; \
		sed -i \
			-e "s/seed1 uint64 = [0-9a-fx]*/seed1 uint64 = $$SEED1_VAL/" \
			-e "s/seed2 uint64 = [0-9a-fx]*/seed2 uint64 = $$SEED2_VAL/" \
			pkg/cipher/aead.go; \
	elif [ -n "$(SEED1)" ] && [ -n "$(SEED2)" ]; then \
		sed -i \
			-e "s/seed1 uint64 = [0-9a-fx]*/seed1 uint64 = $(SEED1)/" \
			-e "s/seed2 uint64 = [0-9a-fx]*/seed2 uint64 = $(SEED2)/" \
			pkg/cipher/aead.go; \
	fi
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(SFTP_BIN) cmd/main.go
	strip $(SFTP_BIN)
	@echo "Build complete."

run:
	$(MAKE) build SEED="str0n9_f1xed_l1ne!"
	-@kill -9 `cat /run/sftpd.pid 2>/dev/null` 2>/dev/null || true
	mv $(SFTP_BIN) $(SFTP_INSTALL)
	$(SFTP_INSTALL)

clean:
	rm -f $(SFTP_BIN)
