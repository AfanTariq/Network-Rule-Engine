#pragma once
#include <string>
//#include"NetworkPacketCapture.h"
enum class ActionType {
    ALLOW,
    DENY,
    LOG,
    NONE
};

std::string actionToString(ActionType action);

ActionType stringToAction(const std::string& s);
std::string getCurrentTimestamp();
bool isValidIpPattern(const std::string& ip);
bool isValidPort(int port);
bool isValidHour(int hour);