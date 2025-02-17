TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
CFLAGS := -O3 -Ideps/molecule -I deps/secp256k1/src -I deps/secp256k1 -I c -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
MOLC := moleculec
MOLC_VERSION := 0.2.4

# docker pull xxuejie/riscv-gnu-toolchain-rv64imac:xenial-20190606
BUILDER_DOCKER := xxuejie/riscv-gnu-toolchain-rv64imac@sha256:4f71556b7ea8f450243e2b2483bca046da1c0d76c2d34d120aa0fbf1a0688ec0

all: specs/cells/secp256k1_blake160_sighash_all specs/cells/dao specs/cells/secp256k1_ripemd160_sha256_sighash_all

all-via-docker: c/protocol_reader.h
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/secp256k1_blake160_sighash_all: c/secp256k1_blake160_sighash_all.c c/protocol_reader.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

specs/cells/dao: c/dao.c c/protocol_reader.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

specs/cells/secp256k1_ripemd160_sha256_sighash_all: c/secp256k1_ripemd160_sha256_sighash_all.c c/protocol_reader.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc $(CFLAGS) -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

c/protocol_reader.h: c/ckb.mol
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}
	${MOLC} \
		--language c \
		--schema-file c/ckb.mol \
		> c/protocol_reader.h

install-tools:
	if [ ! -x "$$(command -v "${MOLC}"))" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

publish:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo publish --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo package --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package-clean:
	git checkout Cargo.toml Cargo.lock
	rm -rf Cargo.toml.bak target/package/

clean:
	rm -rf specs/cells/secp256k1_blake160_sighash_all specs/cells/dao
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -rf specs/cells/secp256k1_data
	rm -rf spec/cells/secp256k1_ripemd160_sha256_sighash_all
	cd deps/secp256k1 && make clean

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
