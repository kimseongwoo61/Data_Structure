#pragma once
#include <stdio.h>
#include <stdlib.h>


// 파일정보 : 사이즈, 라인 수
typedef struct File_information {
	unsigned int fileSize;
	unsigned int fileRow;
}F_info;


// 파일 분할기능 관련 함수
void analyze_File(char* fileDirectory, F_info* attrbute); //분석 파일의 사이즈와 라인수를 구조체로 저장한다.
unsigned int getLine_Count(FILE* fp);					  //파일의 라인수를 반환한다.
unsigned int getFile_Size(FILE* fp);					  //파일의 용량정보를 반환한다. 
int fileSpliter(char* inputDir, char* baseDir, int line);  //파일 경로와 분할 파일저장경로, 분할할 줄수를 입력받아 분할작업을 진행한다.
