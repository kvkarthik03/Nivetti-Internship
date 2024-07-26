#include <pcap.h>
#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap file>" << std::endl;
        return 1;
    }

    const char* filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename, errbuf);

    if (handle == NULL) {
        std::cerr << "Couldn't open pcap file " << filename << ": " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char* packet;
    int packet_count = 0;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        std::cout << "Packet #" << ++packet_count << std::endl;
        std::cout << "Timestamp: " << header.ts.tv_sec << "." << header.ts.tv_usec << std::endl;
        std::cout << "Length: " << header.len << " bytes" << std::endl;
        std::cout << std::endl;
    }

    pcap_close(handle);
    return 0;
}

