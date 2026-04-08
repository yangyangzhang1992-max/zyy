# RISC-V Secure Boot Image Verification Library
#
# Target: RISC-V with K extension (Zk) for SHA acceleration
#         + Vector Extension (V) for ECDSA point multiplication
# Build: riscv64-unknown-elf-gcc with -march=rv64gcv_zk

CC = riscv64-unknown-elf-gcc
CFLAGS_COMMON = -Wall -Wextra -O2

INC = -I./include \
       -I./thirdparty/riscv-crypto/benchmarks/share \
       -I./thirdparty/riscv-crypto/benchmarks/sha256 \
       -I./thirdparty/riscv-crypto/benchmarks/sha512 \
       -I./thirdparty/mbedtls/include

AR = riscv64-unknown-elf-ar

SRC = src
OBJ = obj

RISCV_CRYPTO = thirdparty/riscv-crypto
MBEDTLS = thirdparty/mbedtls/library/libmbedcrypto.a
TARGET = libsecure_boot.a

# Build with K + V extensions (SHA + ECDSA)
CFLAGS_KV = $(CFLAGS_COMMON) $(INC) \
            -march=rv64gcv_zk -mabi=lp64d \
            -D__riscv_zk -D__riscv_rvv

# Build with K extension only (SHA, no ECDSA vector)
CFLAGS_K = $(CFLAGS_COMMON) $(INC) \
            -march=rv64gc_zk -mabi=lp64d \
            -D__riscv_zk

# Minimal build (no crypto extensions, pure software)
CFLAGS_BASE = $(CFLAGS_COMMON) $(INC) -march=rv64gc

.PHONY: all clean image_tool mbedtls riscv_crypto build-kv build-k build-base

all: build-kv

# Default: K + V extensions (full acceleration)
build-kv: CFLAGS = $(CFLAGS_KV)
build-kv: $(TARGET)
	@echo "Built with K + V extensions (SHA + ECDSA)"

$(TARGET): $(OBJ)/hash.o $(OBJ)/ecdsa.o $(OBJ)/verify.o $(OBJ)/ecdsa_pubkey.o
	$(AR) rcs $@ $^

# Hash module with K extension (SHA)
$(OBJ)/hash.o: $(SRC)/hash.c | $(OBJ)
	$(CC) $(CFLAGS_KV) $(INC) -c $< -o $@

# ECDSA module with RVV (point multiplication)
$(OBJ)/ecdsa.o: $(SRC)/ecdsa.c | $(OBJ)
	$(CC) $(CFLAGS_KV) $(INC) -c $< -o $@

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(CC) $(CFLAGS_KV) $(INC) -c $< -o $@

$(OBJ)/ecdsa_pubkey.o: keys/ecdsa_pubkey.c | $(OBJ)
	$(CC) $(CFLAGS_KV) $(INC) -c $< -o $@

$(OBJ):
	mkdir -p $(OBJ)

# Image tool for creating signed images
image_tool: $(OBJ)/image_tool.o $(OBJ)/hash.o $(OBJ)/ecdsa.o $(OBJ)/ecdsa_pubkey.o
	$(CC) $(CFLAGS_KV) $^ -o $@ -L./thirdparty/mbedtls/library -lmbedcrypto -lm

# Build with K extension only (no RVV for ECDSA)
build-k: CFLAGS = $(CFLAGS_K)
build-k: $(TARGET)
	@echo "Built with K extension only (SHA via intrinsics, ECDSA via mbedTLS)"

# Build base (no crypto extensions, pure software)
build-base: CFLAGS = $(CFLAGS_BASE)
build-base: $(TARGET)
	@echo "Built base (pure software)"

# Fetch riscv-crypto submodule
$(RISCV_CRYPTO):
	git submodule update --init thirdparty/riscv-crypto

# Fetch mbedTLS submodule
$(MBEDTLS): thirdparty/mbedtls
	git submodule update --init thirdparty/mbedtls

thirdparty/mbedtls:
	git submodule add https://github.com/Mbed-TLS/mbedtls.git thirdparty/mbedtls
	cd thirdparty/mbedtls && git checkout v3.6.0

mbedtls: $(MBEDTLS)
	cd thirdparty/mbedtls && make -j4 libmbedcrypto.a

riscv_crypto: $(RISCV_CRYPTO)
	@echo "riscv-crypto submodule ready at $(RISCV_CRYPTO)"

clean:
	rm -rf $(OBJ) $(TARGET)
	cd thirdparty/mbedtls && make clean 2>/dev/null || true

cleanall: clean
	rm -rf thirdparty/riscv-crypto thirdparty/mbedtls

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/include
	install -m 644 include/*.h $(DESTDIR)/usr/local/include/
	install -m 644 $(TARGET) $(DESTDIR)/usr/local/lib/
