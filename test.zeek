# Copyright 2020 by Jason Xu
#
# This is a testing file, DO NOT use it.

global agentTable :table[addr] of set[string] = table();

event agent_detect(c: connection, name: string) {
	local orig_addr: addr = c$id$orig_h;
	if (c$http?$user_agent){
		local agent: string = to_lower(c$http$user_agent);
		if (orig_addr in agentTable) {
			add agentTable[orig_addr][agent];
		} else {
			agentTable[orig_addr] = set(agent);
		}
	}
}

event zeek_done() {
	for (orig_addr in agentTable) {
		if (|agentTable[orig_addr][agent]| >= 3) {
			print orig_addr," is a proxy";
		}
	}
}
