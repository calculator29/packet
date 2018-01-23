#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <pthread.h>

struct PLIST{
  struct PLIST *next;
  u_int32_t ip, sport, dport;
  int len;
}plist = {NULL,0,0,0,0};

void setPLIST( u_int32_t ip, u_int32_t sport, u_int32_t dport, int len ){
  struct PLIST *cell, *cell_new;
  cell=&plist;
  while(1){
    // 同じipアドレスがなかった場合作成
    if( cell->next==NULL || cell->next->ip > ip ){
      cell_new = (struct PLIST*)malloc(sizeof(struct PLIST));
      cell_new->ip = ip; cell_new->sport = sport; cell_new->dport = dport; cell_new->len = len;
      cell_new->next = cell->next;
      cell->next = cell_new;
      break;
    }

    // 次へ進む
    cell=cell->next;

    // 同じipアドレスが見つかった場合処理
    if( cell->ip == ip && cell->sport == sport && cell->dport == dport ){
      if( ( cell->len += len ) > 1000 ) cell->len = 1000;
      return;
    }
  }
}

void updatePLIST(){
  struct PLIST *cell, *cell_old;
  cell=&plist;
  while(1){
    if(cell->next==NULL) break;
    cell_old = cell;
    cell=cell->next;

    cell->len -= 10;
    if(cell->len < 0){
      cell_old->next = cell->next;
      free(cell);
      cell = cell_old;
    }
  }
}

void printPLIST(){
  int i;
  struct PLIST *cell = &plist;

  system("clear");
  while(1){
    if( cell->next==NULL ) break;
    else cell=cell->next;

    printf("%d.%d.%d.%d\n", (cell->ip>>0)&255, (cell->ip>>8)&255, (cell->ip>>16)&255, (cell->ip>>24)&255 );
    while(1){
      printf("  %d->%d\t", cell->sport, cell->dport);
      for(i=0;i<(double)cell->len/100.0;i++) printf("■"); printf("\n");
      if( cell->next==NULL || cell->ip != cell->next->ip ) break;
      else cell=cell->next;
    };

    printf("\n");
  }
}







void print_thread( void ){
  while(1){
    printPLIST();
    updatePLIST();
    usleep(500000);
  }
}

#define SETIP(a,b,c,d) ( a<<0 | b<<8 | c<<16 | d<<24 )
void get_packet( u_char *arg, const struct pcap_pkthdr *h, const u_char *p ){
  struct ip *ip;
  struct tcphdr *tcp;

  if( h->len < sizeof(struct ether_header)+sizeof(struct ip)+sizeof(struct tcphdr) ) return;
  ip = (struct ip *)(p+sizeof(struct ether_header));
  tcp = (struct tcphdr *)(p+sizeof(struct ether_header)+sizeof(struct ip));
  if( ip->ip_dst.s_addr != SETIP(160,16,74,85) ) return;

  setPLIST(ip->ip_src.s_addr, ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohs(ip->ip_len));
}

#define DPCP_RCV_MAXSIZE   68
#define DPCP_PROMSCS_MODE  1
#define DPCP_RCV_TIMEOUT   1000
#define DPCP_NOLIMIT_LOOP  -1

int main( void ){
  pcap_t *handle = NULL;
  char ebuf[PCAP_ERRBUF_SIZE];

  char dev[]      = "ens3";
  char protocol[] = "tcp";

  // デバイスオープン
  if( (handle = pcap_open_live( dev, DPCP_RCV_MAXSIZE, DPCP_PROMSCS_MODE, DPCP_RCV_TIMEOUT, ebuf )) == NULL ){printf("デバイスが開けません、実行許可を確認してください。\n");return -1;}

  // フィルター設定
  struct bpf_program fp;
  bpf_u_int32 net;
  if( pcap_compile( handle, &fp, protocol, 0, net) == -1 ){printf("フィルターコンパイルエラー\n");return -1;}
  if( pcap_setfilter( handle, &fp) == -1 ){printf("フィルター設定エラー\n");return -1;}


  pthread_t thread;
  pthread_create( &thread, NULL, (void *)print_thread, NULL );
  if( pcap_loop( handle, DPCP_NOLIMIT_LOOP, get_packet, NULL ) < 0 ){printf("実行できませんでした。\n");return -1;}

  pcap_close( handle );
  return 0;
}
