#include "TimeBasedRule.h"
#include<chrono>
#include <iomanip>
bool TimeBasedRule::matches(const Packet& packet, int currentHour) const {
    if (!Rule::matches(packet, currentHour)) {
        return false;
    }
    int hourToCheck = currentHour;
    if (hourToCheck == -1) {
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm;
        localtime_s(&now_tm, &now_time_t); // Safe replacement
        hourToCheck = now_tm.tm_hour;
    }
    return (hourToCheck >= startHour && hourToCheck <= endHour);
}

void TimeBasedRule::display() const {
    Rule::display(); // Call base display
    std::cout << "          └─ Active Hours: [" << std::setfill('0') << std::setw(2) << startHour << ":00 - "
        << std::setfill('0') << std::setw(2) << endHour << ":59]" << std::setfill(' ') << std::endl;
}

// EXPLANATION: TimeBasedRule::toCsvString() implementation
// Calls the base class's toCsvString and appends its specific fields.
// For simplicity, we'll reconstruct the string here. A better way might be to have base return a stream.
// Or, more simply, just serialize all fields directly. The first field indicates type.
std::string TimeBasedRule::toCsvString() const {
    std::stringstream ss;
    ss << "TimeBased," // Rule Type identifier
        << id << ","
        << "\"" << name << "\"," // Enclose name in quotes
        << sourceIpPattern << ","
        << destinationIpPattern << ","
        << sourcePortPattern << ","
        << destinationPortPattern << ","
        << protocolPattern << ","
        << actionToString(action) << ","
        << priority << ","
        << startHour << "," // Additional fields for TimeBasedRule
        << endHour;
    return ss.str();
}

