#include "Class.h"
#include<sstream>
#include<chrono>

#include <iomanip>
std::string actionToString(ActionType action) {
    switch (action) {
    case ActionType::ALLOW: return "ALLOW";
    case ActionType::DENY:  return "DENY";
    case ActionType::LOG: return "LOG";
    case ActionType::NONE:  return "NONE";
    default:                return "UNKNOWN";
    }
}

// Helper function to convert a string (from file) back to ActionType.
ActionType stringToAction(const std::string& s) {
    if (s == "ALLOW") return ActionType::ALLOW;
    if (s == "DENY") return ActionType::DENY;
    if (s == "LOG") return ActionType::LOG;
    return ActionType::NONE; // Default or if unknown
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);

    std::tm now_tm;
    localtime_s(&now_tm, &now_time_t); // Safer, thread-safe version

    std::stringstream ss;
    ss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

bool isValidIpPattern(const std::string& ip) {
    if (ip.empty() || ip == "ANY") return true;

    std::string ip_part = ip;
    std::string cidr_part = "";
    size_t slash_pos = ip.find('/');

    if (slash_pos != std::string::npos) {
        ip_part = ip.substr(0, slash_pos);
        cidr_part = ip.substr(slash_pos + 1);
    }

    std::stringstream ss(ip_part);
    std::string segment;
    int octet_count = 0;

    // Validate IPv4 part (four octets)
    while (std::getline(ss, segment, '.')) {
        octet_count++;
        if (octet_count > 4) return false; // Too many segments

        try {
            int octet = std::stoi(segment);
            if (octet < 0 || octet > 255) return false; // Octet out of range
        }
        catch (const std::exception& e) {
            return false; // Not a valid integer
        }
    }

    if (octet_count != 4) return false; // Must have exactly 4 octets

    // Validate CIDR part if present
    if (!cidr_part.empty()) {
        try {
            int cidr_val = std::stoi(cidr_part);
            if (cidr_val < 0 || cidr_val > 32) return false; // CIDR mask out of range
        }
        catch (const std::exception& e) {
            return false; // Not a valid integer
        }
    }

    return true; // Passed all checks
}


bool isValidPort(int port) {
    return port == -1 || (port >= 0 && port <= 65535);
}

bool isValidHour(int hour) {
    return hour >= 0 && hour <= 23;
}