#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <direct.h>
#include <io.h> 
#include <process.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <time.h> 
#include <Windows.h>
#include <direct.h>
#include <sys/types.h>


/*tshark ���� ���� : ____[��Ŷ ������ȣ]_[�ð�����]_[�۽���ip]_��_[������ip]_[�������� ����]_[�׿� ������ �������� �߰� ����]*/
typedef struct pcapText_Line { 
	char seqNum[10];
	char time[20];
	char sendAddr[20];
	char recvAddr[20];
	char protocol[20]; //????
	char option[2000];   //???? ���� ��Ȯ�� ��� ����� �𸣸�, ���� ����� ���ɼ��� ����.
}pcapInfo;

typedef struct _parsingResult { //�ؼ� ����� ����Ǵ� ��� ����ü
	pcapInfo data;				  // ����� ������ ����ü(�����Ҵ��� ����ǹǷ� �����ͷ� �޴´�.)
	struct _parsingResult* next;  // ���� ����� �ּ� ������
}parsingResult;

typedef struct File_information {
	unsigned int fileSize;
	unsigned int fileRow;
}F_info;



typedef struct arg {
	char fullDirectory[200];
	char search_type[100];
	char broadcast_Addr[16];
	parsingResult* Node;
}file_parsing;



extern HANDLE hthread[1000];
extern parsingResult* lastNode;
extern CRITICAL_SECTION cs;
extern HANDLE hMutex;
parsingResult* List_create();
void List_insert(parsingResult** target, parsingResult* newNode); // ��带 Ư�� �ε����� �����Ѵ�.
void List_delete(parsingResult* target); // Ư�� �ε����� ��ġ�� ��带 �����Ѵ�.
int List_count(parsingResult* target);   // ����Ʈ�� ���� ������ ������ �ش�. -> ���� ����Ʈ���� �迭�� ��ȯ�� Ȱ�밡��


//-----------------------------------------------------------------------------------------------------------------



// �������� : ������, ���� ��



// ���� ���ұ�� ���� �Լ�
void analyze_File(char* fileDirectory, F_info* attrbute); //�м� ������ ������� ���μ��� ����ü�� �����Ѵ�.
unsigned int getLine_Count(FILE* fp);					  //������ ���μ��� ��ȯ�Ѵ�.
unsigned int getFile_Size(FILE* fp);					  //������ �뷮������ ��ȯ�Ѵ�. 
int fileSpliter(char* inputDir, char* baseDir, int line);  //���� ��ο� ���� ����������, ������ �ټ��� �Է¹޾� �����۾��� �����Ѵ�.


//-------------------------------------------



void logScaner(char* getLine, pcapInfo* output);    // �α� ������ ������ ����ü�� �����Ѵ�.
//



typedef struct _finddata_t FILE_SEARCH;

file_parsing* readThread(char* path, FILE_SEARCH file_search, char* search_point, int index);
parsingResult* GetfileList(char* path, char* search_point); //Ư�� ������ ���� ��θ� Ž���ϴ� �ڵ�
unsigned int __stdcall Thread_R(void* lpParam);
//
int landAttack(pcapInfo* checker);					// �ۼ������� IP ������ ��ġ�ϸ� count���� �ø��� �ش� ����ü ������ �����Ѵ�.
int suspicious_syn_Flood(pcapInfo* checker);      // tcp ���������� ack �÷��׸� �����Ͽ� ������ ��� ������ ��� �˻�
int suspicious_Smurf(char* brocastAddr, pcapInfo* checker);
