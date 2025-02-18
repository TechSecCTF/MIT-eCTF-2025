CC = gcc
CFLAGS = -Wall -Wextra -I../wolfssl -I../decoder/inc -D_DECODER_POC -DWOLFSSL_NO_OPTIONS_H -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING

WOLFCRYPT_SRC = ../wolfssl/wolfcrypt/src
WOLFCRYPT_FILES = sha.c sha256.c logging.c wc_port.c md5.c hash.c memory.c

SRC = src/main.c src/secrets.c src/cryptosystem.c \
      $(addprefix $(WOLFCRYPT_SRC)/, $(WOLFCRYPT_FILES))
OBJ = $(SRC:.c=.o)
DEPS = src/secrets.h src/cryptosystem.h

TARGET = decoder

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

src/secrets.c src/secrets.h: gen_secret_sources.py secrets.json
	python gen_secret_sources.py secrets.json

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
