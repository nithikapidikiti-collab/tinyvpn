OPENSSL_PREFIX = /opt/homebrew/opt/openssl@3
CC      = clang
CFLAGS  = -Wall -Wextra -O2 -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
SRC     = src/main.c src/tunnel.c src/crypto.c
BIN     = tinyvpn
all: $(BIN)
$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
clean:
	rm -f $(BIN)
