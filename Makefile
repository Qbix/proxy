# Makefile — Build Qbix proxy (structural security proxy for PHP).
#
# Produces a standalone binary that structurally sanitizes every HTTP
# request before forwarding it to PHP-FPM (FastCGI) or HTTP backends.
# No TLS, HTTP/2, WebSocket, PHP embedding, static files, or ZIP —
# Qbix proxy sits behind nginx/caddy for TLS termination.
#
# Targets:
#   make                      Dynamic-linked (development)
#   make static               musl-gcc static Linux binary
#   make cosmo                Cosmopolitan APE (cross-platform)
#   make clean

SHELL   := /bin/bash

# ── compiler selection ──────────────────────────────────────────────
CC_DYN   ?= gcc
CC_MUSL  ?= musl-gcc
CC_COSMO ?= cosmocc

# ── flags ───────────────────────────────────────────────────────────
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-format-truncation
CFLAGS  += -std=gnu11 -pthread -ffunction-sections -fdata-sections
LDFLAGS_DYN  = -Wl,--gc-sections
LDFLAGS_MUSL = -Wl,--gc-sections -static
LDFLAGS_COSMO =

# Only -lpthread — no libssl, libcrypto, libnghttp2, libz
LDLIBS  = -lpthread

# ── source files ────────────────────────────────────────────────────
CORE    := src/util.c src/http.c src/sanitize.c src/fastcgi.c src/proxy.c
INFRA   := src/config.c src/stats.c src/route.c src/loop.c
STUBS   := src/tls_stub.c src/h2_stub.c src/ws_stub.c src/static_stub.c \
           src/zipfs_stub.c src/php_stub.c src/process_stub.c src/relay_stub.c

SRC     := $(CORE) $(INFRA) $(STUBS)
HEADERS := src/userver.h src/platform.h src/cosmo_compat.h

# ── output ──────────────────────────────────────────────────────────
BUILD    := build
BIN_DYN  := $(BUILD)/qbixproxy
BIN_MUSL := $(BUILD)/qbixproxy-static
BIN_COSMO:= $(BUILD)/qbixproxy.com

# ── targets ─────────────────────────────────────────────────────────
.PHONY: all static cosmo clean

all: $(BIN_DYN)

$(BIN_DYN): $(SRC) $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC_DYN) $(CFLAGS) $(LDFLAGS_DYN) -o $@ $(SRC) $(LDLIBS)
	@echo "→ $@ ($$(du -sh $@ | cut -f1))"

static: $(BIN_MUSL)

$(BIN_MUSL): $(SRC) $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC_MUSL) $(CFLAGS) $(LDFLAGS_MUSL) -o $@ $(SRC) $(LDLIBS)
	strip $@
	@echo "→ $@ (static, $$(du -sh $@ | cut -f1))"

cosmo: $(BIN_COSMO)

$(BIN_COSMO): $(SRC) $(HEADERS)
	@mkdir -p $(BUILD)
	$(CC_COSMO) $(CFLAGS) $(LDFLAGS_COSMO) -o $@ $(SRC) $(LDLIBS)
	@echo "→ $@ (cosmopolitan APE, $$(du -sh $@ | cut -f1))"

clean:
	rm -rf $(BUILD)
