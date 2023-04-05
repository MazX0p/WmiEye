# Compiler settings.
CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Werror

# Program settings.
PROGRAM = sigma_wmi_event_monitor
SOURCES = main.c sigmarules.c eventlog.c elastic.c
OBJECTS = $(SOURCES:.c=.o)
LIBS = -lwinhttp -lyaml

# Directories.
SRC_DIR = src
BIN_DIR = bin

all: $(BIN_DIR)/$(PROGRAM)

$(BIN_DIR)/$(PROGRAM): $(addprefix $(SRC_DIR)/, $(OBJECTS))
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(addprefix $(SRC_DIR)/, $(OBJECTS)) $(BIN_DIR)/$(PROGRAM)

.PHONY: all clean
