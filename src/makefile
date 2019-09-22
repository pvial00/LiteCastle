CC=gcc
CFLAGS=-O3 -std=c99 -w
TARGET=lcastle
all: $(TARGET)

$(TARGET): castle.c
	$(CC) castle.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
