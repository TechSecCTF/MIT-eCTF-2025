CC = gcc
CFLAGS = -Wall -Wextra $(shell pkg-config --cflags wolfssl)
LDFLAGS = $(shell pkg-config --libs wolfssl)

SRC = src/main.c src/secrets.c
OBJ = $(SRC:.c=.o)
DEPS = src/secrets.h

TARGET = decoder

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

src/secrets.c src/secrets.h: gen_secrets.py secrets.json
	python ./gen_secrets.py secrets.json

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
