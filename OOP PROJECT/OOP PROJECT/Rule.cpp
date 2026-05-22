#include "Rule.h"
#include <iomanip>


 #include "Packet.h" 

// Constructor implementation
bool Rule::matches(const Packet& packet, int /*currentHour*/) const {
if (!sourceIpPattern.empty() && sourceIpPattern != "ANY" && sourceIpPattern != packet.sourceIp) return false;
if (!destinationIpPattern.empty() && destinationIpPattern != "ANY" && destinationIpPattern != packet.destinationIp) return false;
if (sourcePortPattern != -1 && sourcePortPattern != packet.sourcePort) return false;
if (destinationPortPattern != -1 && destinationPortPattern != packet.destinationPort) return false;
if (!protocolPattern.empty() && protocolPattern != "ANY" && protocolPattern != packet.protocol) return false;
return true;
}

void Rule::display() const {
    std::cout << "Rule ID: " << std::left << std::setw(5) << id
        << "Name: " << std::left << std::setw(30) << name // Increased width for name
        << "SrcIP: " << std::left << std::setw(15) << (sourceIpPattern.empty() ? "ANY" : sourceIpPattern)
        << "DestIP: " << std::left << std::setw(15) << (destinationIpPattern.empty() ? "ANY" : destinationIpPattern)
        << "SrcPort: " << std::left << std::setw(7) << (sourcePortPattern == -1 ? "ANY" : std::to_string(sourcePortPattern))
        << "DestPort: " << std::left << std::setw(7) << (destinationPortPattern == -1 ? "ANY" : std::to_string(destinationPortPattern))
        << "Proto: " << std::left << std::setw(7) << (protocolPattern.empty() ? "ANY" : protocolPattern)
        << "Action: " << std::left << std::setw(7) << actionToString(action)
        << "Prio: " << priority << std::endl;
}


std::string Rule::toCsvString() const {
    std::stringstream ss;
    ss << "Standard," // Rule Type identifier
        << id << ","
        << "\"" << name << "\"," // Enclose name in quotes in case it has commas
        << sourceIpPattern << ","
        << destinationIpPattern << ","
        << sourcePortPattern << ","
        << destinationPortPattern << ","
        << protocolPattern << ","
        << actionToString(action) << ","
        << priority;
    return ss.str();
}
