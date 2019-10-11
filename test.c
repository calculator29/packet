#include<pcap.h>

void dump(const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
	for(i = 0; i < length; i++) {
		byte = data_buffer[i];
		printf(" %02x", data_buffer[i]);
		if((i % 16 == 15) || (i == length-1)) {
			for(j = 0; j < 15-(i%16); j++) {
				printf("   ");
			}
			printf("| ");
			for(j = (i - (i%16)); j <= i; j++) {
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127))
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}


int main() {
	struct pcap_pkthdr header;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *pcap_handle;
	int i;

	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		printf("error\n");
		return 1;
	}
	printf("device = %s\n", device);

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	if (pcap_handle == NULL) {
		printf("error\n");
		return 1;
	}

	for (int i = 0; i < 3; i++) {
		packet = pcap_next(pcap_handle, &header);
		printf("packet size = %d\n", header.len);
		dump(packet, header.len);
	}

	pcap_close(pcap_handle);

	return 0;
}