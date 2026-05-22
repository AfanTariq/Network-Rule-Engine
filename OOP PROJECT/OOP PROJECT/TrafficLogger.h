#pragma once
#include <fstream>
#include <string>
#include"Class.h"

 #include "Packet.h" // Packet is defined above

#include <iomanip>
 enum class ActionType; // ActionType is defined above

// EXPLANATION: TrafficLogger Class
// Responsible for logging evaluated packets and their outcomes to a file.
class TrafficLogger {
private:
    std::ofstream logFile;
    std::string filename;

public:
    // Constructor: Opens the log file in append mode.
    TrafficLogger(const std::string& logFilename) : filename(logFilename) {
        logFile.open(filename, std::ios::app); // Append to existing file or create new
        if (!logFile.is_open()) {
            std::cerr << "Error: Could not open traffic log file '" << filename << "'." << std::endl;
        }
        else {
            logFile << "--- Traffic Log Started: " << getCurrentTimestamp() << " ---" << std::endl;
        }
    }

    // Destructor: Closes the log file.
    ~TrafficLogger() {
        if (logFile.is_open()) {
            logFile << "--- Traffic Log Ended: " << getCurrentTimestamp() << " ---" << std::endl;
            logFile.close();
        }
    }

    // Logs a packet evaluation event.
    void log(const Packet& packet, ActionType action, int matchingRuleId = -1, const std::string& matchingRuleName = "") {
        if (logFile.is_open()) {
            logFile << "[" << getCurrentTimestamp() << "] "
                << "Packet: (" << packet.toString() << ") -> Action: " << actionToString(action);
            if (matchingRuleId != -1) {
                logFile << ", Matched Rule ID: " << matchingRuleId
                    << (matchingRuleName.empty() ? "" : " (" + matchingRuleName + ")");
            }
            else {
                logFile << ", Reason: Default Action";
            }
            logFile << std::endl;
        }
    }
};