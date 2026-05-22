#pragma once
#include <string>
#include <iostream>
#include<sstream>

class Packet {
public:
    std::string sourceIp;
    std::string destinationIp;
    std::string protocol;
    int sourcePort;
    int destinationPort;
    int length;

    
    Packet();

    
    Packet(const std::string& srcIp, const std::string& destIp,
        int srcPort, int destPort, const std::string& proto, int length);


    
    void display() const;
    std::string toString() const {
        std::stringstream ss;
        ss << "SrcIP: " << sourceIp << ", DstIP: " << destinationIp
            << ", SrcPort: " << sourcePort << ", DstPort: " << destinationPort
            << ", Proto: " << protocol;
        return ss.str();
    }






};

