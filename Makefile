CC = gcc
CFLAGS = -Wall -Werror -std=c99 -pedantic -g -O3
LDLIBS = -lm

OUT_DIR = exe

all: directories aes_cbc

directories:
	@mkdir -p $(OUT_DIR)


aes_cbc: aes.c aes_cbc.c
	$(CC) $(CFLAGS) -o $(OUT_DIR)/$@ $^ $(LDLIBS)

clean:
	rm -rf $(OUT_DIR)
