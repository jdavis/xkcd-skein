WARNINGS = -Wall
CC = gcc
CFLAGS = -O3 $(WARNINGS)
TARGET = xkcd
LIBS = -lcurl
DEPS = SHA3api_ref.o skein.o skein_block.o crack.o
TESTDEPS = skein.o skein_block.o tests.o  

all: $(DEPS) $(TARGET) $(TESTS)

tests: $(TESTDEPS)
	$(CC) $(CFLAGS) -o test $(TESTDEPS)

$(TARGET): $(DEPS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(DEPS) $(LFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

clean:
	rm --force *.o
	rm --force $(TARGET)
