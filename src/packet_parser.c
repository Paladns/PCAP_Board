#include "packet_parser.h"
#include <stdio.h>
#include <string.h>

const char* get_protocol_name(uint8_t protocol) {
    return "";
}


int parse_packet(const u_char *packet, uint32_t len, PacketInfo *info) {
    return 0;
}


void get_tcp_flags_str(uint8_t flags, char *buf, int buf_size) {
}