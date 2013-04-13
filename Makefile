WARNINGS = -Wall --pedantic
CC = gcc
CFLAGS = -O3 $(WARNINGS)
TARGET = xkcd
LIBS = -lcurl
DEPS = skein.o crack.o

all: $(DEPS) $(TARGET) $(TESTS)

$(TARGET): $(DEPS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(DEPS) $(LFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

clean:
	rm --force *.o
	rm --force $(TARGET)
