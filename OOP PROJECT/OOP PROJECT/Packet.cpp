#include "Packet.h"


Packet::Packet()
    : sourceIp("0.0.0.0"), destinationIp("0.0.0.0"), protocol("UNKNOWN"),
    sourcePort(-1), destinationPort(-1), length(0) {
}


Packet::Packet(const std::string& srcIp, const std::string& destIp,
    int srcPort, int destPort, const std::string& proto, int len)
    : sourceIp(srcIp), destinationIp(destIp), sourcePort(srcPort),
    destinationPort(destPort), protocol(proto), length(len) {
}


void Packet::display() const {
    std::cout << "Packet: [SrcIP: " << sourceIp
        << ", DestIP: " << destinationIp
        << ", SrcPort: " << sourcePort
        << ", DestPort: " << destinationPort
        << ", Protocol: " << protocol
        << ", Length: " << length << "]" << std::endl;
}
