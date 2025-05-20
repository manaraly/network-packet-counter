# Compiler and linker
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpcap

# Source files and target binaries
SOURCES = main.c packet_parser.c
TEST_SOURCES = test_parser.c packet_parser.c
HEADERS = packet_parser.h
TARGET = packet_counter
TEST_TARGET = test_parser

# Default target
all: $(TARGET) $(TEST_TARGET)

# Build the main application
$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# Build the test application
$(TEST_TARGET): $(TEST_SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(TEST_SOURCES) $(LDFLAGS)

# Clean up build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGET) *.o

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Install the application
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Uninstall the application
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build the main application and tests (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  test     - Run tests"
	@echo "  install  - Install the application to /usr/local/bin"
	@echo "  uninstall- Remove the application from /usr/local/bin"
	@echo "  help     - Display this help message"

.PHONY: all clean test install uninstall help