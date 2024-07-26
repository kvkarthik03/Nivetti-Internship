#include <iostream>
#include <pcap.h>
#include <string>
#include <cstring>
#include <openssl/sha.h>
#include <curl/curl.h>

// Function to calculate SHA256 hash
std::string sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Function to query AlienVault OTX API
bool check_malware(const std::string& hash) {
    CURL* curl;
    CURLcode res;
    std::string api_key = "your_alienvault_api_key";
    std::string url = "https://otx.alienvault.com/api/v1/indicators/file/" + hash + "/analysis";

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, ("X-OTX-API-KEY: " + api_key).c_str());
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            // Process the response to check if the file is malicious
            // For simplicity, assume the response contains the "malware" keyword if malicious
            // You should parse the JSON response for a proper check
            std::string response;
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            if (response.find("malware") != std::string::npos) {
                curl_easy_cleanup(curl);
                curl_global_cleanup();
                return true;
            }
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return false;
}

int main() {
    // Open pcap file
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline("your_pcap_file.pcap", errbuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open pcap file: " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Process packet to extract HTTP Content-Type and file content
        // Assume we have a function to extract file content called extract_file_content
        std::string file_content = extract_file_content(packet, header);

        if (!file_content.empty()) {
            std::string hash = sha256(file_content);
            if (check_malware(hash)) {
                std::cout << "Malware detected in file with hash: " << hash << std::endl;
            } else {
                std::cout << "File is clean: " << hash << std::endl;
            }
        }
    }

    pcap_close(handle);
    return 0;
}
