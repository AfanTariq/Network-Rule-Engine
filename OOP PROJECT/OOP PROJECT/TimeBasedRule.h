#pragma once
 #include "Rule.h" // Base class is Rule
#include<string>
#include<chrono>// For time operations
// EXPLANATION: TimeBasedRule Class (Derived Class)
// Inherits from the 'Rule' class. This demonstrates the "is-a" relationship (a TimeBasedRule "is a" Rule).
// It adds time-specific conditions to the basic rule matching.

#include <chrono>

class TimeBasedRule : public Rule {
private:
    int startHour;
    int endHour;

public:
    TimeBasedRule(int id, const std::string& name,
        const std::string& srcIp, const std::string& destIp,
        int srcPort, int destPort,
        const std::string& proto, ActionType act,
        int priority, int startH, int endH)
        : Rule(id, name, srcIp, destIp, srcPort, destPort, proto, act, priority),
        startHour(startH), endHour(endH) {
        if (startHour < 0 || startHour > 23 || endHour < 0 || endHour > 23 || startHour > endHour) {
            std::cerr << "Warning: Invalid start/end hours (" << startH << "-" << endH
                << ") for TimeBasedRule ID " << id << ". Defaulting to 0-23." << std::endl;
            this->startHour = 0; this->endHour = 23;
        }
    }

    bool matches(const Packet& packet, int currentHour = -1) const override;
    void display() const override;

    // EXPLANATION: Override toCsvString for TimeBasedRule specific fields
    std::string toCsvString() const override;

    int getStartHour() const { return startHour; }
    int getEndHour() const { return endHour; }
    void setStartHour(int hour) { if (hour >= 0 && hour <= 23) startHour = hour; }
    void setEndHour(int hour) { if (hour >= 0 && hour <= 23) endHour = hour; }
};