CC=gcc
CFLAGS=-O3 -std=c99 -w -lssl -lcrypto -std=c99 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
TARGET=lcastle
all: $(TARGET)

$(TARGET): castle.c
	$(CC) castle.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
