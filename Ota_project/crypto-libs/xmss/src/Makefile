CC ?= gcc
AR ?= ar

XMSS_MODE ?= 1
CPPFLAGS += -DXMSS_MODE=$(XMSS_MODE) -I. -I../../fips202/src
CFLAGS ?= -O2 -Wall -Wextra

SOURCES = \
	XMSS_core_fast.c \
	XMSS_commons.c \
	XMSS_hash.c \
	XMSS_hash_address.c \
	XMSS_hash_wrapper.c \
	XMSS_randombytes.c \
	XMSS_sha256.c \
	XMSS_wots.c \
 	XMSS_xmss.c
OBJECTS = $(SOURCES:.c=.o) fips202.o
TARGET = libxmss.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

fips202.o: ../../fips202/src/fips202.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
