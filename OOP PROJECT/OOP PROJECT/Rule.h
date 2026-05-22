#pragma once
#include <string>

 #include "Packet.h" // Packet definition needed for matches()
#include"Class.h"
#include<sstream>

 enum class ActionType; // ActionType enum needed

 class Rule {
 public:
     int id;
     std::string name;
     std::string sourceIpPattern;
     std::string destinationIpPattern;
     int sourcePortPattern;
     int destinationPortPattern;
     std::string protocolPattern;
     ActionType action;
     int priority;

     Rule(int id, const std::string& name,
         const std::string& srcIp, const std::string& destIp,
         int srcPort, int destPort,
         const std::string& proto, ActionType act, int priorityParam = 0)
         : id(id), name(name), sourceIpPattern(srcIp), destinationIpPattern(destIp),
         sourcePortPattern(srcPort), destinationPortPattern(destPort),
         protocolPattern(proto), action(act), priority(priorityParam) {}

     virtual ~Rule() = default;

     virtual bool matches(const Packet& packet, int currentHour = -1) const;
     virtual void display() const;
     virtual std::string toCsvString() const;

     ActionType getAction() const { return action; }
     int getId() const { return id; }
     const std::string& getName() const { return name; }
     int getPriority() const { return priority; }
     const std::string& getSourceIpPattern() const { return sourceIpPattern; }
     const std::string& getDestinationIpPattern() const { return destinationIpPattern; }
     int getSourcePort() const { return sourcePortPattern; }
     int getDestinationPort() const { return destinationPortPattern; }
     const std::string& getProtocol() const { return protocolPattern; }


     void setName(const std::string& newName) { name = newName; }
     void setAction(ActionType newAction) { action = newAction; }
     void setPriority(int newPriority) { priority = newPriority; }
     void setSourceIpPattern(const std::string& pattern) { sourceIpPattern = pattern; }
     void setDestinationIpPattern(const std::string& pattern) { destinationIpPattern = pattern; }
     void setSourcePortPattern(int port) { sourcePortPattern = port; }
     void setDestinationPortPattern(int port) { destinationPortPattern = port; }
     void setProtocolPattern(const std::string& proto) { protocolPattern = proto; }
 };
