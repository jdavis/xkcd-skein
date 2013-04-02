WARNINGS = -Wall
CC = gcc
CFLAGS = $(WARNINGS)
TARGET = xkcd
LIBS = -lcurl
DEPS = skein.o skein_block.o crack.o

all: $(DEPS) $(TARGET)

$(TARGET): $(DEPS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(DEPS) $(LFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm *.o
