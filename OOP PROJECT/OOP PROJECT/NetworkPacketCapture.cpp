#include "NetworkPacketCapture.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <pcap.h>
#include <ws2tcpip.h> // Windows TCP/IP utilities
#include <winsock2.h> // Windows Sockets API
#include"BasicFileEncryptor.h"
#include<ctime>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#include <fstream>
#include "Class.h"
#include <chrono>

void NetworkPacketCapture::logPacketToFiles(const Packet& pkt,
    ActionType action,
    const std::string& logFile,
    const std::string& encryptedFile,
    const std::string& key)
{
    // Get current time
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);

    char buffer[26];
    ctime_s(buffer, sizeof(buffer), &now_time);
    std::string timestamp(buffer);
    timestamp.pop_back(); // remove trailing newline

    // Create full log entry
    std::string logEntry = timestamp + " - " + pkt.toString() +
        " - Action: " + actionToString(action);

    // Plaintext log
    std::ofstream plainLog(logFile, std::ios::app);
    if (plainLog.is_open()) {
        plainLog << logEntry << "\n";
    }

    // Encrypted log
    std::ofstream encLog(encryptedFile, std::ios::binary | std::ios::app);
    if (encLog.is_open()) {
        encLog << BasicFileEncryptor::encrypt(logEntry + "\n", key);
    }
}




NetworkPacketCapture::NetworkPacketCapture(const std::string& device)
    : handle(nullptr), deviceName(device), isCapturing(false) {
    memset(errbuf, 0, sizeof(errbuf));
}

NetworkPacketCapture::~NetworkPacketCapture() {
    stopCapture();
}

// In NetworkPacketCapture.cpp
#include <cstring> // For memset

std::vector<NetworkDevice> NetworkPacketCapture::listAvailableDevices() {
    std::vector<NetworkDevice> device_system_names;
    
    pcap_if_t* alldevs = nullptr;
    char local_errbuf[PCAP_ERRBUF_SIZE];
    memset(local_errbuf, 0, sizeof(local_errbuf));



    if (pcap_findalldevs(&alldevs, local_errbuf) == -1) {
        std::cerr << "Error finding devices during pcap_findalldevs: " << local_errbuf << std::endl;
        return device_system_names; // Return empty vector
    }

    bool devices_found_in_loop = false;
    if (alldevs) { // Only print header if devices might be listed
        std::cout << "\nAvailable network devices:" << std::endl;
        int index = 1;
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next, ++index) {
            devices_found_in_loop = true;
            std::string current_device_name = "UNKNOWN_DEVICE_NAME_NULL"; // Default if d->name is NULL
            if (d->name) {
                NetworkDevice dev;
                dev.name = d->name ? d->name : "";
                dev.description = d->description ? d->description : "";
                // Add more fields if needed
                device_system_names.push_back(dev);
            }
           // device_system_names.push_back(current_device_name); // Store the system name

            // Print the user-friendly list entry
            std::cout << index << ". ";
            if (d->description && d->description[0] != '\0') {
                std::cout << d->description;
                //current_device_name = d->description;
                //device_system_names.push_back(current_device_name); // Store the system name
            } else { // Fallback to system name if description is not useful
                std::cout << current_device_name;
            }
            std::cout << std::endl;

            // Add device to combo box
         
        }
    }

    pcap_freealldevs(alldevs);

    // The main function will check if device_system_names is empty and print a message.
    // So, no "No network devices found!" message is strictly needed here if alldevs was NULL
    // or the loop didn't add any devices.

    return device_system_names;





}

bool NetworkPacketCapture::setDevice(const std::string& device) {
    deviceName = device;
    handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    return handle != nullptr;
}

bool NetworkPacketCapture::startCapture(int packetCount) {
    if (!handle) {
        std::cerr << "Capture handle not initialized!" << std::endl;
        return false;
    }

    return pcap_loop(handle, packetCount, packet_handler, nullptr) >= 0;
}

void NetworkPacketCapture::stopCapture() {
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}

void NetworkPacketCapture::packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::cout << "Captured packet of length: " << pkthdr->len << " bytes" << std::endl;
}

Packet NetworkPacketCapture::captureOnePacket() {
    if (deviceName.empty()) {
        std::cerr << "Device not set." << std::endl;
        return Packet();
    }

    pcap_t* captureHandle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!captureHandle) {
        std::cerr << "Failed to open device for capture: " << errbuf << std::endl;
        return Packet();
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int result = pcap_next_ex(captureHandle, &header, &data);

    Packet pkt;
    if (result > 0 && header->len >= 34) {
        const u_char* ip_header = data + 14; // Ethernet offset
        int protocol = ip_header[9];

        char src_ip[16], dst_ip[16];
        snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
        snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u", ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

        pkt.sourceIp = src_ip;
        pkt.destinationIp = dst_ip;
        pkt.protocol = (protocol == 6 ? "TCP" : (protocol == 17 ? "UDP" : "OTHER"));

        const u_char* transport = ip_header + (ip_header[0] & 0x0F) * 4;
        pkt.sourcePort = (transport[0] << 8) | transport[1];
        pkt.destinationPort = (transport[2] << 8) | transport[3];
    }

    pcap_close(captureHandle);
    return pkt;
}
