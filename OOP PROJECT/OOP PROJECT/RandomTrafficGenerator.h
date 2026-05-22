#pragma once
#include <random>   // For std::default_random_engine, std::uniform_int_distribution
#include <string>   // For std::string, std::to_string
#include <vector>   // For std::vector
#include <sstream>  // For std::stringstream
#include <chrono>   // For std::chrono (seeding)
 #include "Packet.h" // Packet is defined above

class RandomTrafficGenerator {
private:
   
    std::default_random_engine generator;

    // EXPLANATION: Distributions to map raw random numbers to desired ranges.
    // For IP octets (0-255)
    std::uniform_int_distribution<int> ipOctetDist;
    // For port numbers (1-65535, common range, though 0 is also valid)
    std::uniform_int_distribution<int> portDist;
    // For selecting a protocol from our list
    std::uniform_int_distribution<int> protocolDist;

    // EXPLANATION: A list of common protocols to choose from.
    std::vector<std::string> protocols;

public:
    // EXPLANATION: Constructor
    // Initializes distributions and seeds the random number generator.
    RandomTrafficGenerator()
        : ipOctetDist(0, 255),             // IP octets range from 0 to 255
        portDist(1, 65535),            // Ports range from 1 to 65535
        protocols({ "TCP", "UDP", "ICMP" }) // List of protocols
    {
       
        unsigned seed = std::chrono::steady_clock::now().time_since_epoch().count();
        generator.seed(seed);

        // Initialize protocolDist based on the size of the protocols vector.
        // This ensures we only generate valid indices for the vector.
        if (!protocols.empty()) {
            protocolDist = std::uniform_int_distribution<int>(0, protocols.size() - 1);
        }
        else {
            // Handle empty protocols vector case, though unlikely with hardcoded list
            protocolDist = std::uniform_int_distribution<int>(0, 0);
        }
    }

    // EXPLANATION: Generates a random IP address string (e.g., "192.168.1.10").
    std::string generateRandomIp() {
        std::stringstream ss;
        // Generate four octets for the IP address.
        ss << ipOctetDist(generator) << "." << ipOctetDist(generator) << "."
            << ipOctetDist(generator) << "." << ipOctetDist(generator);
        return ss.str();
    }

    // EXPLANATION: Generates a random port number.
    int generateRandomPort() {
        return portDist(generator);
    }

    // EXPLANATION: Generates a random protocol string from the predefined list.
    std::string generateRandomProtocol() {
        if (protocols.empty()) {
            return "N/A"; // Fallback if protocols list is somehow empty
        }
        // Use protocolDist to get a random index into the protocols vector.
        return protocols[protocolDist(generator)];
    }
    std::uniform_int_distribution<int> lengthDist{ 64, 1500 };  // Ethernet frame size range

    int generateRandomLength() {
        return lengthDist(generator);
    }


    // EXPLANATION: Generates a complete random Packet object.
    // This method orchestrates the generation of each part of the packet.
    Packet generatePacket() {
        return Packet(generateRandomIp(),    // Random source IP
            generateRandomIp(),    // Random destination IP
            generateRandomPort(),  // Random source port
            generateRandomPort(),  // Random destination port
            generateRandomProtocol(),
            generateRandomLength()); // Random protocol
    }
};