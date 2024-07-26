#include <iostream>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>

using namespace std;
using namespace pcpp;
using namespace CryptoPP;

void processPacket(RawPacket* packet) {
    Packet parsedPacket(packet);

    // Extract HTTP layer
    // let's get the HTTP request layer
pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::httprequestlayer>();
if (httpRequestLayer == NULL)
{
    std::cerr << "Something went wrong, couldn't find HTTP request layer" << std::endl;
    return;
}

    // Filter for specific Content-Type
    if (httpLayer->getContentType() != "application/octet-stream")
        return;

    // Extract payload (file data)
    PayloadLayer* payloadLayer = parsedPacket.getLayerOfType<PayloadLayer>();
    if (!payloadLayer)
        return;

    // Compute hash (SHA-256) of the payload
    string payloadData = payloadLayer->getDataAsString();
    SHA256 sha256;
    pcpp::byte hash[SHA256::DIGESTSIZE];
    sha256.CalculateDigest(hash, (byte*)payloadData.c_str(), payloadData.length());

    // Print or store hash
    cout << "SHA-256 hash: ";
    StringSource(hash, sizeof(hash), true, new HexEncoder(new FileSink(cout)));
    cout << endl;
}

int main() {
    // Open a live capture or read from pcap file
    PcapLiveDevice* dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("your_interface_name_or_pcap_file_path");
    if (dev == nullptr) {
        cerr << "Failed to open device or file" << endl;
        return 1;
    }

    if (!dev->open()) {
        cerr << "Failed to open device or file" << endl;
        return 1;
    }

    // Set a filter to capture HTTP traffic
    string filter = "tcp port 80 or tcp port 8080"; // Customize as needed
    if (!dev->setFilter(filter)) {
        cerr << "Failed to set filter" << endl;
        return 1;
    }

    // Capture packets and process them
    dev->startCapture(processPacket);

    // Cleanup
    dev->stopCapture();
    dev->close();

    return 0;
}
