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


/*tshark 리턴 형식 : ____[패킷 순서번호]_[시간정보]_[송신지ip]_→_[수신지ip]_[프로토콜 종류]_[그외 각각의 프로토콜 추가 정보]*/
typedef struct pcapText_Line { 
	char seqNum[10];
	char time[20];
	char sendAddr[20];
	char recvAddr[20];
	char protocol[20]; //????
	char option[2000];   //???? 아직 정확한 멤버 사이즈를 모르며, 추후 변경될 가능성이 있음.
}pcapInfo;

typedef struct _parsingResult { //해석 결과가 저장되는 노드 구조체
	pcapInfo data;				  // 저장될 데이터 구조체(동적할당이 진행되므로 포인터로 받는다.)
	struct _parsingResult* next;  // 다음 노드의 주소 포인터
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
void List_insert(parsingResult** target, parsingResult* newNode); // 노드를 특정 인덱스에 삽입한다.
void List_delete(parsingResult* target); // 특정 인덱스에 위치한 노드를 삭제한다.
int List_count(parsingResult* target);   // 리스트의 원소 개수를 리턴해 준다. -> 추후 리스트에서 배열로 변환시 활용가능


//-----------------------------------------------------------------------------------------------------------------



// 파일정보 : 사이즈, 라인 수



// 파일 분할기능 관련 함수
void analyze_File(char* fileDirectory, F_info* attrbute); //분석 파일의 사이즈와 라인수를 구조체로 저장한다.
unsigned int getLine_Count(FILE* fp);					  //파일의 라인수를 반환한다.
unsigned int getFile_Size(FILE* fp);					  //파일의 용량정보를 반환한다. 
int fileSpliter(char* inputDir, char* baseDir, int line);  //파일 경로와 분할 파일저장경로, 분할할 줄수를 입력받아 분할작업을 진행한다.


//-------------------------------------------



void logScaner(char* getLine, pcapInfo* output);    // 로그 한줄의 정보를 구조체에 저장한다.
//



typedef struct _finddata_t FILE_SEARCH;

file_parsing* readThread(char* path, FILE_SEARCH file_search, char* search_point, int index);
parsingResult* GetfileList(char* path, char* search_point); //특정 폴더의 하위 경로를 탐색하는 코드
unsigned int __stdcall Thread_R(void* lpParam);
//
int landAttack(pcapInfo* checker);					// 송수신지의 IP 정보가 일치하면 count값을 올리고 해당 구조체 정보를 리턴한다.
int suspicious_syn_Flood(pcapInfo* checker);      // tcp 프로토콜의 ack 플래그를 설정하여 보내는 통신 내역을 모두 검색
int suspicious_Smurf(char* brocastAddr, pcapInfo* checker);
