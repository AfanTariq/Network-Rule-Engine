#pragma once
#include <vector>
#include <string>
#include"IRuleConflictResolver.h"
#include"Rule.h"
#include"Packet.h"

#include"Class.h"
#include <memory> // For std::unique_ptr
#include"TrafficLogger.h"
class RuleEngine {
private:
    std::vector<std::unique_ptr<Rule>> rules;
    ActionType defaultAction;
    int nextRuleId;
    std::unique_ptr<IRuleConflictResolver> conflictResolver;
    std::unique_ptr<TrafficLogger> logger;
    Packet parsePacket(const std::string& line, const std::string& format);
    Packet parseCsvPacket(const std::string& line);
public:
    
    const std::vector<std::unique_ptr<Rule>>& getRules() const;

    
    void analyzePacketFile(const std::string& filename, const std::string& format = "csv");
    
    RuleEngine(ActionType defaultAct = ActionType::DENY, const std::string& logFilename = "traffic.log");

    
    void addRule(std::unique_ptr<Rule> rule);
   
    const Rule* getRuleById(int ruleId) const;
    Rule* getMutableRuleById(int ruleId);
   
    bool deleteRule(int ruleId);
    void displayAllRules() const;
    void setConflictResolver(std::unique_ptr<IRuleConflictResolver> resolver);
    int getNextAvailableId();
    bool saveRulesToFile(const std::string& filename, const std::string& format = "csv", const std::string& encryptionKey = "") const;
    bool loadRulesFromFile(const std::string& filename, const std::string& format = "csv", const std::string& encryptionKey = "");
    void clearAllRules();
    std::string analyzePacketFileAndGetResults(const std::string& filename, const std::string& format = "csv");


    ActionType evaluatePacket(const Packet& packet, int currentHour = -1);

};