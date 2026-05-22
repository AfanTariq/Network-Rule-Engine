#pragma once
#include<vector>
class Rule;
class Packet;

class IRuleConflictResolver {
public:
	
	virtual ~IRuleConflictResolver() = default;

	virtual const Rule* resolve(const Packet& packet, const std::vector<const Rule*>& conflictingRules) = 0;




};