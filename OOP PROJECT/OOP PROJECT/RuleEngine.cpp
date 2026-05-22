#include "RuleEngine.h"
#include "TimeBasedRule.h"
#include <iomanip>
#include <iostream>
#include "Rule.h"
#include "IRuleConflictResolver.h"
#include "Class.h"
#include "BasicFileEncryptor.h"
#include <fstream>
#include "PriorityConflictResolver.h"
#include "TrafficLogger.h"
enum class ActionType;

std::string RuleEngine::analyzePacketFileAndGetResults(const std::string& filename, const std::string& format) {
    std::ifstream file(filename);
    std::stringstream results;

    if (!file.is_open()) {
        results << "ERROR: Failed to open packet file: " << filename << "\n";
        return results.str();
    }

    results << "===== PACKET FILE ANALYSIS =====\n";
    results << "File: " << filename << "\n\n";

    std::string line;
    int packetCount = 0;
    int allowedCount = 0;
    int deniedCount = 0;
    int loggedCount = 0;

    // Skip header if CSV
    if (format == "csv" && !file.eof()) {
        std::getline(file, line);
    }

    while (std::getline(file, line)) {
        packetCount++;
        results << "\n--- Packet #" << packetCount << " ---\n";
        results << "Raw data: " << line << "\n";

        try {
            Packet pkt = parsePacket(line, format);
            results << "Details: " << pkt.toString() << "\n";

            ActionType action = evaluatePacket(pkt);
            results << "Action: " << actionToString(action) << "\n";

            switch (action) {
            case ActionType::ALLOW: allowedCount++; break;
            case ActionType::DENY: deniedCount++; break;
            case ActionType::LOG: loggedCount++; break;
            default: break;
            }
        }
        catch (const std::exception& e) {
            results << "ERROR: " << e.what() << "\n";
        }
    }

    results << "\n===== SUMMARY =====\n";
    results << "Total packets: " << packetCount << "\n";
    results << "Allowed: " << allowedCount << "\n";
    results << "Denied: " << deniedCount << "\n";
    results << "Logged: " << loggedCount << "\n";

    return results.str();
}


RuleEngine::RuleEngine(ActionType defaultAct, const std::string& logFilename)
    : defaultAction(defaultAct), nextRuleId(1), conflictResolver(nullptr) {
    logger = std::make_unique<TrafficLogger>(logFilename);
    setConflictResolver(std::make_unique<PriorityConflictResolver>());
    std::cout << "RuleEngine initialized. Default conflict resolver: PriorityConflictResolver. Logging to: " << logFilename << "." << std::endl;
}

void RuleEngine::addRule(std::unique_ptr<Rule> rule) {
    if (!rule) {
        std::cerr << "Warning: Attempted to add a null rule." << std::endl;
        return;
    }
    if (rule->getName().empty()) {
        std::cerr << "Warning: Rule ID " << rule->getId() << " has an empty name. Rule not added." << std::endl;
        return;
    }
    if (!isValidIpPattern(rule->sourceIpPattern) || !isValidIpPattern(rule->destinationIpPattern)) {
        std::cerr << "Warning: Rule ID " << rule->getId() << " has invalid IP pattern(s). Rule not added." << std::endl;
        return;
    }
    if (!isValidPort(rule->sourcePortPattern) || !isValidPort(rule->destinationPortPattern)) {
        std::cerr << "Warning: Rule ID " << rule->getId() << " has invalid port(s). Rule not added." << std::endl;
        return;
    }

    if (rule->getId() >= nextRuleId) nextRuleId = rule->getId() + 1;
    rules.push_back(std::move(rule));
}

const Rule* RuleEngine::getRuleById(int ruleId) const {
    auto it = std::find_if(rules.begin(), rules.end(),
        [ruleId](const std::unique_ptr<Rule>& r) { return r->getId() == ruleId; });
    return (it != rules.end()) ? it->get() : nullptr;
}

Rule* RuleEngine::getMutableRuleById(int ruleId) {
    auto it = std::find_if(rules.begin(), rules.end(),
        [ruleId](const std::unique_ptr<Rule>& r) { return r->getId() == ruleId; });
    return (it != rules.end()) ? it->get() : nullptr;
}

bool RuleEngine::deleteRule(int ruleId) {
    auto it = std::remove_if(rules.begin(), rules.end(),
        [ruleId](const std::unique_ptr<Rule>& r) { return r->getId() == ruleId; });
    if (it != rules.end()) {
        rules.erase(it, rules.end());
        return true;
    }
    return false;
}
const std::vector<std::unique_ptr<Rule>>& RuleEngine::getRules() const {
    return rules;
}

void RuleEngine::displayAllRules() const {
    if (rules.empty()) {
        std::cout << "No rules loaded." << std::endl;
        return;
    }
    std::cout << "\n--- Current Rules ---" << std::endl;
    for (const auto& r : rules) r->display();
    std::cout << "---------------------" << std::endl;
}

void RuleEngine::setConflictResolver(std::unique_ptr<IRuleConflictResolver> resolver) {
    conflictResolver = std::move(resolver);
    std::cout << (conflictResolver ? "Conflict resolver has been set." : "Conflict resolver has been cleared.") << std::endl;
}

int RuleEngine::getNextAvailableId() { return nextRuleId++; }

bool RuleEngine::saveRulesToFile(const std::string& filename, const std::string& format, const std::string& encryptionKey) const {
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        std::cerr << "Error saving to " << filename << std::endl;
        return false;
    }

    std::stringstream ss;
    ss << "RuleType,ID,Name,SrcIP,DestIP,SrcPort,DestPort,Protocol,Action,Priority,StartHour,EndHour\n";
    for (const auto& rule_ptr : rules)
        ss << rule_ptr->toCsvString() << "\n";

    std::string content = ss.str();
    if (!encryptionKey.empty()) {
        content = BasicFileEncryptor::encrypt(content, encryptionKey);
    }

    outFile.write(content.data(), content.size());
    std::cout << "Rules saved to " << filename << std::endl;
    return true;
}

std::vector<std::string> parseCsvLine_phase3(const std::string& line) {
    std::vector<std::string> fields;
    std::string currentField;
    bool inQuotes = false;

    for (char c : line) {
        if (c == '"') {
            inQuotes = !inQuotes;
        }
        else if (c == ',' && !inQuotes) {
            fields.push_back(currentField);
            currentField.clear();
        }
        else {
            currentField += c;
        }
    }
    fields.push_back(currentField);
    return fields;
}

bool RuleEngine::loadRulesFromFile(const std::string& filename, const std::string& format, const std::string& encryptionKey) {
    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        std::cerr << "Error loading from " << filename << std::endl;
        return false;
    }

    std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    if (!encryptionKey.empty()) fileContent = BasicFileEncryptor::decrypt(fileContent, encryptionKey);

    std::stringstream ss(fileContent);
    std::string line;
    std::getline(ss, line);
    if (line.find("RuleType") == std::string::npos) ss.seekg(0);

    clearAllRules();
    int maxIdLoaded = 0;

    while (std::getline(ss, line)) {
        if (line.empty()) continue;

        std::vector<std::string> f = parseCsvLine_phase3(line);
        if (f.size() < 10) {
            std::cerr << "Warning: Malformed line (too few fields): " << line << std::endl;
            continue;
        }

        try {
            int id = std::stoi(f[1]);
            std::string name = f[2].empty() ? "Unnamed Rule" : f[2];
            std::string srcIp = isValidIpPattern(f[3]) ? f[3] : "ANY";
            std::string dstIp = isValidIpPattern(f[4]) ? f[4] : "ANY";

            int srcPort = (f[5] == "ANY" || f[5].empty()) ? -1 : std::stoi(f[5]);
            int dstPort = (f[6] == "ANY" || f[6].empty()) ? -1 : std::stoi(f[6]);

            std::string proto = f[7].empty() ? "ANY" : f[7];
            ActionType act = stringToAction(f[8]);
            if (act == ActionType::NONE) act = ActionType::DENY;

            int prio = f[9].empty() ? 0 : std::stoi(f[9]);

            if (id > maxIdLoaded) maxIdLoaded = id;

            if (f[0] == "Standard") {
                addRule(std::make_unique<Rule>(id, name, srcIp, dstIp, srcPort, dstPort, proto, act, prio));
            }
            else if (f[0] == "TimeBased" && f.size() >= 12) {
                int startH = f[10].empty() ? 0 : std::stoi(f[10]);
                int endH = f[11].empty() ? 23 : std::stoi(f[11]);
                addRule(std::make_unique<TimeBasedRule>(id, name, srcIp, dstIp, srcPort, dstPort, proto, act, prio, startH, endH));
            }
            else {
                std::cerr << "Warning: Unknown or malformed rule type in line: " << line << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error parsing line: " << line << " - " << e.what() << std::endl;
        }
    }

    nextRuleId = maxIdLoaded + 1;
    std::cout << "Rules loaded from " << filename << ". Next ID: " << nextRuleId << std::endl;
    return true;
}

void RuleEngine::clearAllRules() {
    rules.clear();
    nextRuleId = 1;
    std::cout << "All rules cleared." << std::endl;
}

ActionType RuleEngine::evaluatePacket(const Packet& packet, int currentHour) {
    packet.display();
    std::cout << "Evaluating packet (Simulated Hour: " << (currentHour == -1 ? "System" : std::to_string(currentHour)) << ")..." << std::endl;

    std::vector<const Rule*> matchedRules;
    for (const auto& r : rules) {
        if (r->matches(packet, currentHour)) matchedRules.push_back(r.get());
    }

    ActionType finalAction = defaultAction;
    const Rule* effectiveRule = nullptr;

    if (matchedRules.empty()) {
        std::cout << "No rule matched. Default action: " << actionToString(defaultAction) << std::endl;
    }
    else {
        std::cout << matchedRules.size() << " rule(s) matched. ";
        effectiveRule = conflictResolver ? conflictResolver->resolve(packet, matchedRules)
            : *std::max_element(matchedRules.begin(), matchedRules.end(),
                [](const Rule* a, const Rule* b) {
                    return a->getPriority() < b->getPriority();
                });
        finalAction = effectiveRule ? effectiveRule->getAction() : defaultAction;
        std::cout << "Final decision by Rule ID: " << (effectiveRule ? std::to_string(effectiveRule->getId()) : "None")
            << ". Action: " << actionToString(finalAction) << std::endl;
    }

    if (logger) {
        if (effectiveRule)
            logger->log(packet, finalAction, effectiveRule->getId(), effectiveRule->getName());
        else
            logger->log(packet, finalAction);
    }

    return finalAction;
}


void RuleEngine::analyzePacketFile(const std::string& filename, const std::string& format) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "ERROR: Failed to open packet file: " << filename << std::endl;
        return;
    }

    std::cout << "\n===== PACKET FILE ANALYSIS STARTED =====\n";
    std::cout << "Reading from: " << filename << "\n\n";

    std::string line;
    int packetCount = 0;

    // Skip header if CSV
    if (format == "csv" && !file.eof()) {
        std::getline(file, line);
        std::cout << "Skipping header: " << line << std::endl;
    }

    while (std::getline(file, line)) {
        packetCount++;
        std::cout << "\n--- Processing Packet #" << packetCount << " ---" << std::endl;
        std::cout << "Raw data: " << line << std::endl;

        try {
            Packet pkt = parsePacket(line, format);
            std::cout << "Parsed packet details:\n";
            pkt.display();

            std::cout << "\nRule Evaluation Results:\n";
            evaluatePacket(pkt);
        }
        catch (const std::exception& e) {
            std::cerr << "ERROR processing packet #" << packetCount
                << ": " << e.what() << std::endl;
        }
    }

    std::cout << "\n===== ANALYSIS COMPLETE =====\n";
    std::cout << "Processed " << packetCount << " packets from file.\n";
}

Packet RuleEngine::parsePacket(const std::string& line, const std::string& format) {
    if (format == "csv") {
        return parseCsvPacket(line);
    }
    throw std::runtime_error("Unsupported packet file format: " + format);
}

Packet RuleEngine::parseCsvPacket(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    std::stringstream ss(line);

    while (std::getline(ss, field, ',')) {
        fields.push_back(field);
    }

    if (fields.size() < 5) {
        throw std::runtime_error("Invalid CSV format - expected at least 5 fields");
    }

    Packet pkt;
    pkt.sourceIp = fields[0];
    pkt.destinationIp = fields[1];

    try {
        pkt.sourcePort = std::stoi(fields[2]);
        pkt.destinationPort = std::stoi(fields[3]);
    }
    catch (...) {
        throw std::runtime_error("Invalid port number in packet data");
    }

    pkt.protocol = fields[4];
    pkt.length = (fields.size() > 5) ? std::stoi(fields[5]) : 0;

    return pkt;
}