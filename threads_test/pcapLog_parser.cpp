#pragma once
#include "pcapLog_parser.h"


void logScaner(char* getLine, pcapInfo* output) {
	char *ptr;
	int count = 1;
	ptr = strtok(getLine, " ");
	strcpy(output->seqNum, ptr);    //������ȣ ����

	ptr = strtok(NULL, " ");        //�ð����� ����
	strcpy(output->time, ptr);

	ptr = strtok(NULL, " ");
	strcpy(output->sendAddr, ptr);  //�۽��� ip ���� ����

	ptr = strtok(NULL, " ");
	
	ptr = strtok(NULL, " ");
	strcpy(output->recvAddr, ptr);  //������ ip ���� ����

	ptr = strtok(NULL, " ");
	strcpy(output->protocol,  ptr); //�������� ���� ����
}

