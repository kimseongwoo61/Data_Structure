#include "file_Operation.h"
#include <direct.h>
#include <string.h>


void analyze_File(char* fileDirectory, F_info* attrbute) {

	FILE* fp = fopen(fileDirectory, "r");
	if (fp == NULL) {
		printf("파일경로를 잘못 입력하셨습니다.");
		return;
	}

	attrbute->fileRow = getLine_Count(fp);
	attrbute->fileSize = getFile_Size(fp);
	fclose(fp);
}


unsigned int getLine_Count(FILE *fp) {
	int lineCounter = 0;
	char lastWord;

	while ((lastWord = fgetc(fp)) != EOF) {
		if (lastWord == '\n')
			lineCounter++;
	}
	return lineCounter;
}


unsigned int getFile_Size(FILE *fp) {
	int size = 0;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);

	return size;
}

int fileSpliter(char* inputDir, char* baseDir, int line) {
	/*
		인자:
			1. 분할할 파일경로
			2. 분할된 파일 저장경로
			3. 분할할 줄 수

		결과
			1. 분할된 파일들.

		error
			-1 - 분할할 파일의 경로가 올바르지 않습니다.
			-2 - 분할된 파일의 경로가 올바르지 않습니다.
			-3 - 알수 없는 에러가 발생하였습니다.
			 0 - 인자가 부족합니다.
			 1 - 성공
	*/

	char base[100];				// 분할된 파일 저장경로
	char tmp[5];				// 분할된 파일뒤에 붙는 숫자. ex) log1, log2, ...
	char analyzeFile[100];		// 분할할 파일의 경로
	char newDirectory[100];		// 분할된 파일을 write하기 위한 세부경로
	char filename[100] = "log";	// 분할된 파일 이름

	if (inputDir == NULL || baseDir == NULL)
		return 0; // 인자정보가 부족합니다.

	strcpy(analyzeFile, inputDir);
	strcpy(base, baseDir);

	int file_counter = 0;
	int counter = 0;

	FILE* fp1;
	FILE* fp = fopen(analyzeFile, "r");
	if (fp == NULL)
		return -1; //분할할 파일의 경로가 올바르지 않습니다.

	_mkdir(base);


	while (!feof(fp)) {

		sprintf(tmp, "%d", file_counter);
		strcpy(newDirectory, base);		// "C:/Users/kimse/Desktop/pcaplog/"
		strcat(newDirectory, filename); // "C:/Users/kimse/Desktop/pcaplog/log"
		strcat(newDirectory, tmp);		// "C:/Users/kimse/Desktop/pcaplog/log0"
		file_counter++;

		fp1 = fopen(newDirectory, "a");
		if (fp == NULL)
			return -2; //분할된 파일저장 경로가 올바르지 않습니다.

		char tmp_chr;
		int count = 0;
		while (!feof(fp)) {
			tmp_chr = fgetc(fp);
			printf("%c", tmp_chr);
			fprintf(fp1, "%c", tmp_chr);
			if (tmp_chr == '\n')
				count++;

			if (count == line) {
				fclose(fp1);
				break;
			}
		}
	}
	fclose(fp);
	return 1;
}


