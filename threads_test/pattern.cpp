#pragma once
#include "pattern.h"

int MACHING_COUNTER = 0;

pcapInfo* landAttack(pcapInfo* checker) { 
	if (checker->recvAddr == checker->sendAddr)
		return checker;
	else
		return NULL;
}


pcapInfo* suspicious_syn_Flood(pcapInfo* checker) {
	char* p;
	char option[4] = "ACK";
	if (checker->protocol == "TCP") {
		p = strstr(checker->option, option);
		if (p)
			return checker;
	}
	else
		return NULL;
}


pcapInfo* suspicious_Smurf(char* brocastAddr, pcapInfo* checker) { //brocast_Addr = 192.168.0.
	if (checker->protocol == "ICMP" && strstr(checker->sendAddr, brocastAddr))
		return checker;
	else
		return NULL;
}
