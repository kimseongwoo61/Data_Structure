#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct pcapText_Line {
	// tshark 리턴 형식 : ____[패킷 순서번호]_[시간정보]_[송신지ip]_→_[수신지ip]_[프로토콜 종류]_[그외 각각의 프로토콜 추가 정보]
	// _ : 공백

	char seqNum[6];
	char time[12];
	char sendAddr[16];
	char recvAddr[16];
	char protocol[10]; //????
	char option[20];   //???? 아직 정확한 멤버 사이즈를 모르며, 추후 변경될 가능성이 있음.

}pcapInfo;


void logScaner(char* getLine, pcapInfo* output);    // 로그 한줄의 정보를 구조체에 저장한다.
