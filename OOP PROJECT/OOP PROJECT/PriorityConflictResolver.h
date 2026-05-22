#pragma once
 #include "IRuleConflictResolver.h" // IRuleConflictResolver is defined above
 #include "Rule.h" // Rule is defined above
 #include <vector>
 #include <algorithm> // For std::max_element

// EXPLANATION: PriorityConflictResolver Class
// A concrete implementation of IRuleConflictResolver.
// Resolves conflicts by choosing the rule with the highest priority.
class PriorityConflictResolver : public IRuleConflictResolver {
public:
    const Rule* resolve(const Packet& /*packet*/, const std::vector<const Rule*>& conflictingRules) override {
        if (conflictingRules.empty()) {
            return nullptr;
        }
        auto highestPriorityRuleIt = std::max_element(conflictingRules.begin(), conflictingRules.end(),
            [](const Rule* a, const Rule* b) {
                return a->getPriority() < b->getPriority();
            });
        return *highestPriorityRuleIt;
    }
};