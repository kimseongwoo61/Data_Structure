#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct pcapText_Line {
	// tshark ���� ���� : ____[��Ŷ ������ȣ]_[�ð�����]_[�۽���ip]_��_[������ip]_[�������� ����]_[�׿� ������ �������� �߰� ����]
	// _ : ����

	char seqNum[6];
	char time[12];
	char sendAddr[16];
	char recvAddr[16];
	char protocol[10]; //????
	char option[20];   //???? ���� ��Ȯ�� ��� ����� �𸣸�, ���� ����� ���ɼ��� ����.

}pcapInfo;


void logScaner(char* getLine, pcapInfo* output);    // �α� ������ ������ ����ü�� �����Ѵ�.
