# Built only inside build.sh's pinned container. libsodium is linked statically (no rpath, no LD_LIBRARY_PATH).
MODULE_big = mr_ed25519
OBJS = mr_ed25519.o
EXTENSION = mr_ed25519
DATA = mr_ed25519--1.0.sql
SODIUM ?= /build/sodium
PG_CPPFLAGS = -I$(SODIUM)/include
SHLIB_LINK = $(SODIUM)/lib/libsodium.a
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
