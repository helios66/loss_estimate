#ifndef _HASHSAMP_H
#define _HASHSAMP_H


#define TCP_SYN 1
#define TCP_ACK 2
#define TCP_RST 4
#define TCP_FIN 8
#define TCP_PSH 16

struct sample {
  unsigned int source_ip;
  unsigned int dest_ip;
  unsigned int sourceport;
  unsigned int destport;
  unsigned int sequence;
  unsigned int tcp_flags;
  unsigned int protocol;
  unsigned long long timestamp;
};

#endif
