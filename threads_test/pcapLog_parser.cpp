#pragma once
#include "pcapLog_parser.h"


void logScaner(char* getLine, pcapInfo* output) {
	char *ptr;
	int count = 1;
	ptr = strtok(getLine, " ");
	strcpy(output->seqNum, ptr);    //순서번호 복사

	ptr = strtok(NULL, " ");        //시간정보 복사
	strcpy(output->time, ptr);

	ptr = strtok(NULL, " ");
	strcpy(output->sendAddr, ptr);  //송신지 ip 정보 복사

	ptr = strtok(NULL, " ");
	
	ptr = strtok(NULL, " ");
	strcpy(output->recvAddr, ptr);  //수신지 ip 정보 복사

	ptr = strtok(NULL, " ");
	strcpy(output->protocol,  ptr); //프로토콜 정보 복사
}

