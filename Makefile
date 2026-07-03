# Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
NPCAP_INC = D:/homework/_shark/resources/npcap-sdk-1.16/Include
NPCAP_LIB = D:/homework/_shark/resources/npcap-sdk-1.16/Lib/x64
TARGET = build/pcap-parser.exe
SRC = src/main.c src/pcap_reader.c src/packet_parser.c src/filter.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	if not exist build mkdir build
	$(CC) $(CFLAGS) -I$(NPCAP_INC) $(SRC) -o $(TARGET) -L$(NPCAP_LIB) -lwpcap -lws2_32

clean:
	if exist build rmdir /s /q build