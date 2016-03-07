#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <stdbool.h>

typedef struct packet_s {
  struct icmphdr icmp;
  struct timeval time;
  uint8_t nonce[128/8];
  uint8_t hmac[256/8];
} packet_t;

typedef struct ping_request_s {
  uint32_t num_pings;
  uint32_t timeout_ms;
  uint8_t key[128/8];
  char ip[64];
} ping_request_t;

unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum=0;
  unsigned short result;

  for ( sum = 0; len > 1; len -= 2 )
    sum += *buf++;
  if ( len == 1 )
    sum += *(unsigned char*)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

void display_ip(struct iphdr *ip) {
  struct in_addr saddr = {ip->saddr};
  struct in_addr daddr = {ip->daddr};
  printf("IPv%d: hdr-size=%d pkt-size=%d protocol=%d TTL=%d src=%s ",
      ip->version, ip->ihl*4, ntohs(ip->tot_len), ip->protocol,
      ip->ttl, inet_ntoa(saddr));
  printf("dst=%s\n", inet_ntoa(daddr));
}

void display_icmp(struct icmphdr *icmp) {
printf("ICMP: type[%d/%d] checksum[%d] id[%d] seq[%d]\n",
    icmp->type, icmp->code, ntohs(icmp->checksum),
    icmp->un.echo.id, icmp->un.echo.sequence);
}

void display(void *buf, int bytes) {  
  int i;
  for ( i = 0; i < bytes; i++ ) {
    if ( !(i & 15) ) printf("\n%03d:  ", i);
    printf("%02X ", ((unsigned char*)buf)[i]);
  }
  printf("\n\n");
}

typedef struct ping_result_s {
  uint64_t time_ms;
  uint64_t ttl;
} ping_result_t;

void *collect_responses(void *);

bool ping(const ping_request_t* request, ping_result_t *result) {
  pthread_t thread;
  pthread_create(&thread, NULL, collect_responses, request);

  //make address
  struct sockaddr_in addr;
  memset(&addr,0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr.s_addr = inet_addr(request->ip);

  //open socket
  int sock; 
  sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
  if ( sock < 0 ) {
      goto error;
  }

  //set ttl to 2 hops
  int ttl=2;
  if ( setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
      goto error;
 
  //build request header
  packet_t request_pkt;
  int i;
  for(i = 0; i < request->num_pings; ++i) {
    memset(&request_pkt,0, sizeof(request_pkt));
    request_pkt.icmp.type = ICMP_ECHO;
    request_pkt.icmp.code = 0;
    if(!RAND_bytes((unsigned char*)&request_pkt.icmp.un.echo.id,sizeof(request_pkt.icmp.un.echo.id))) {
      goto error;
    }
    request_pkt.icmp.un.echo.sequence = 0;
    if(!RAND_bytes((uint8_t*) &request_pkt.nonce, sizeof(request_pkt.nonce))) {
      goto error;
    }
    if(gettimeofday(&request_pkt.time,NULL)) {
      goto error;
    }
    int len=sizeof(request_pkt.hmac);
    if(HMAC(EVP_sha256(), (uint8_t*) request->key, sizeof(request->key), 
      (uint8_t*) &request_pkt.time, sizeof(request_pkt.time) + sizeof(request_pkt.nonce), 
      (uint8_t*) &request_pkt.hmac, &len) == NULL) {
      goto error;
    }
    request_pkt.icmp.checksum = checksum(&request_pkt, sizeof(request_pkt));
    display_icmp(&request_pkt.icmp);
    display(&request_pkt.time, sizeof(request_pkt.time) + sizeof(request_pkt.nonce) + sizeof(request_pkt.hmac));
    if ( sendto(sock, (uint8_t*) &request_pkt, sizeof(request_pkt), 0, (struct sockaddr*) &addr, sizeof(addr)) <= 0 )
      goto error;
  }
  
  pthread_join(thread, NULL);
  return true;

  error: ;
  pthread_join(thread, NULL);
  return false;
}

void* collect_responses(void* data) {
  ping_request_t *request = data;
  //make address
  struct sockaddr_in addr;
  memset(&addr,0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr.s_addr = inet_addr(request->ip);

  //open socket
  int sock; 
  sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
  if ( sock < 0 ) {
    return false;
  }
  //timeout in 100ms -- we should get a ping back from the same rack within 100ms
  struct timeval tv = {0,request->timeout_ms*1000}; //
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0)
    return false;

  int len=sizeof(addr);
  struct timeval now;
  if(gettimeofday(&now,NULL)) {
   return false;
  }
  struct timeval max_time = {now.tv_sec + tv.tv_sec, now.tv_usec + tv.tv_usec};
  int begin = 0;
  int end   = 0;
  int num_responses = 0;
  int sum = 0;
  while (num_responses != request->num_pings && (now.tv_sec <= max_time.tv_sec || 
        (now.tv_sec == max_time.tv_sec && now.tv_usec <= max_time.tv_usec))) {
    uint8_t buf[65536]; // max size

    if(sizeof(buf) - end == 0) {
      // move leftover data to the front of the buffer.
      memmove(buf, buf + begin, end - begin);
      end = end - begin;
      begin = 0;
    }

    if(begin == end) {
      //nothing buffered so start from the beginning
      begin = end = 0;
    }

    int bytes = recvfrom(sock, buf + end, sizeof(buf) - end, 0, (struct sockaddr*)&addr, &len);
    if(gettimeofday(&now,NULL)) {
     return false;
    }
    if(bytes < 0) {
      //TODO
      continue;
    }
    end += bytes;
    next_icmp: ;
    int size = end - begin;
    printf("size %d begin %d end %d\n", size, begin, end);
    if(size < 20) { //smallest ip header
      printf("ip header too small\n");
      continue;
    }

    struct iphdr *ip = (struct iphdr*) buf + begin;
    if(size < ip->ihl*4) {
      printf("ip header not full\n");
      //ip header not fully read
      continue;
    } 
    display_ip(ip);
    size_t ip_len = ntohs(ip->tot_len);

    if(size < ip_len) {
      printf("ip payload not full\n");
      //ip packet not fully read 
      continue;
    }

    if( ip_len != ip->ihl*4 + sizeof(packet_t)) {
      //icmp is of incorrect length -- skip it
      begin += ip_len;
      printf("filtered out\n");
      continue;
    }
      
    packet_t *response = (packet_t*) (buf + ip->ihl*4 + begin);
    begin += ip_len;

    if(response->icmp.type != ICMP_ECHOREPLY || response->icmp.code != 0) {
      printf("filtered out -- concurrent audit pinging\n");
      goto next_icmp;
    }
    uint8_t calculated_hmac[256/8];
    int hmac_len = sizeof(calculated_hmac);
    if(HMAC(EVP_sha256(), (uint8_t*) request->key, sizeof(request->key), 
      (uint8_t*) &response->time, sizeof(response->time) + sizeof(response->nonce), 
      (uint8_t*) calculated_hmac, &hmac_len) == NULL) {
      printf("filtered out -- HMAC failure\n");
      goto next_icmp;
    }
    if(memcmp(response->hmac, &calculated_hmac, sizeof(calculated_hmac))) {
      printf("filtered out -- tampering or concurrent audit pinging\n");
      goto next_icmp;
    }
    uint32_t delta_ms = (now.tv_sec - response->time.tv_sec) * 1000 + (now.tv_usec - response->time.tv_usec + 500) / 1000;
    display_icmp(&response->icmp);
    display(&response->time, sizeof(response->time) + sizeof(response->nonce) + sizeof(response->hmac));
    ++num_responses;
    printf("delta: %ums\n", delta_ms);
    sum += delta_ms;
    goto next_icmp;
  }
  if(num_responses == 0) return NULL;
  printf("delta avg: %dms\n", sum/num_responses);
  printf("exiting\n");
  return NULL;
}

int main(int argc, char **argv) {
  if ( argc != 2 ) {
    printf("usage: %s <ipv4_addr>\n", argv[0]);
    exit(0);
  }
  ping_result_t result;
  ping_request_t request;
  //generate a key for the hmac 
  if(!RAND_bytes((uint8_t*) &request.key,sizeof(request.key))) {
    return false;
  }
  request.num_pings = 10;
  request.timeout_ms = 500;
  memcpy(&request.ip, argv[1], strlen(argv[1])+1);
  ping(&request, &result);
  return 0;
}

