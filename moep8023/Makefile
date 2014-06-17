CC=gcc
CFLAGS=-Wall -O2
LDFALGS=
TARGET=moep8023

SOURCES=src/moep8023.o src/helper.o

OBJECTS=$(SOURCES:.c=.o)


all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFALGS) $(OBJECTS) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -rf $(SOURCES)
	rm -rf $(TARGET)
