#pragma once
#include <stdio.h>
#include <string.h>
#include "pcapLog_parser.h"
#include "linked_list.h"
#include "pattern.h"


int MACHING_COUNTER = 0; //매칭되는 결과를 카운트 하는 전역변수로, 결과 리스트의

pcapInfo* landAttack(pcapInfo* checker);					// 송수신지의 IP 정보가 일치하면 count값을 올리고 해당 구조체 정보를 리턴한다.
pcapInfo* suspicious_TCP_syn_Flood(pcapInfo* checker);      // tcp 프로토콜의 ack 플래그를 설정하여 보내는 통신 내역을 모두 검색
pcapInfo* suspicious_Smurf(pcapInfo* checker);
