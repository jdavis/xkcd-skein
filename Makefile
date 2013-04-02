WARNINGS = -Wall
CC = gcc
CFLAGS = -o3 $(WARNINGS)
TARGET = xkcd
LIBS = -lcurl
DEPS = skein.o skein_block.o crack.o

all: $(DEPS) $(TARGET)

$(TARGET): $(DEPS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(DEPS) $(LFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

clean:
	rm --force *.o
	rm --force $(TARGET)
