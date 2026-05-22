
#pragma once
#include <string>
#include <vector>
#include <pcap.h>  // This is the pcap library for packet capture
#include "Packet.h"
#include "Class.h"

// Add this struct definition (outside the class, or as a public struct inside)
struct NetworkDevice {
    std::string name;
    std::string description;
    
}; 

class NetworkPacketCapture {
private:
    pcap_t* handle;              
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
    std::string deviceName;      
    bool isCapturing;           

    // Static callback function for packet processing
    static void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);

public:
    
    
    void logPacketToFiles(const Packet& pkt, ActionType action, const std::string& logFile, const std::string& encryptedFile, const std::string& key);

    NetworkPacketCapture(const std::string& device = "");

   
    ~NetworkPacketCapture();

    
    std::vector<NetworkDevice> listAvailableDevices();

    
    bool setDevice(const std::string& device);

   
    bool startCapture(int packetCount = 1); // Default to capture just 1 packet

    // Stops the packet capture
    void stopCapture();

    Packet captureOnePacket();

    
    bool isActive() const { return isCapturing; }

   
    std::string getLastError() const { return errbuf; }
};


