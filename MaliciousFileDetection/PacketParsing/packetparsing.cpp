#include <iostream>
#include <stdlib.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/PcapFileDevice.h>

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::TCP:
        return "TCP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
    switch (httpMethod)
    {
    case pcpp::HttpRequestLayer::HttpGET:
        return "GET";
    case pcpp::HttpRequestLayer::HttpPOST:
        return "POST";
    default:
        return "Other";
    }
}

int main(int argc, char *argv[1])
{
    // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
    // and create an interface instance that both readers implement
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("testpcap.pcap");

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        std::cerr << "Cannot determine reader for file type" << std::endl;
        return 1;
    }

    // open the reader for reading
    if (!reader->open())
    {
        std::cerr << "Cannot open input.pcap for reading" << std::endl;
        return 1;
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader->getNextPacket(rawPacket))
    {
        std::cerr << "Couldn't read the first packet in the file" << std::endl;
        return 1;
    }

    // close the file reader, we don't need it anymore
    reader->close();

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
    for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
    {
        std::cout
            << "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; " // get layer type
            << "Total data: " << curLayer->getDataLen() << " [bytes]; "                   // get total length of the layer
            << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; "                 // get the header length of the layer
            << "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]"         // get the payload length of the layer (equals total length minus header length)
            << std::endl;
    }

    // let's get the HTTP request layer
    pcpp::HttpRequestLayer *httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
    if (httpRequestLayer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find HTTP request layer" << std::endl;
        return 1;
    }

    // print HTTP method and URI. Both appear in the first line of the HTTP request
    std::cout << std::endl
              << "HTTP method: " << printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()) << std::endl
              << "HTTP URI: " << httpRequestLayer->getFirstLine()->getUri() << std::endl;

    // print values of the following HTTP field: Host, User-Agent and Cookie
    std::cout
        << "HTTP host: " << httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() << std::endl
        << "HTTP user-agent: " << httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue() << std::endl
        << "HTTP cookie: " << httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue() << std::endl;

    // print the full URL of this request
    std::cout << "HTTP full URL: " << httpRequestLayer->getUrl() << std::endl;
}