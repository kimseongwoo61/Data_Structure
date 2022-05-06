#include "file_Operation.h"
#include <direct.h>
#include <string.h>


void analyze_File(char* fileDirectory, F_info* attrbute) {

	FILE* fp = fopen(fileDirectory, "r");
	if (fp == NULL) {
		printf("���ϰ�θ� �߸� �Է��ϼ̽��ϴ�.");
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
		����:
			1. ������ ���ϰ��
			2. ���ҵ� ���� ������
			3. ������ �� ��

		���
			1. ���ҵ� ���ϵ�.

		error
			-1 - ������ ������ ��ΰ� �ùٸ��� �ʽ��ϴ�.
			-2 - ���ҵ� ������ ��ΰ� �ùٸ��� �ʽ��ϴ�.
			-3 - �˼� ���� ������ �߻��Ͽ����ϴ�.
			 0 - ���ڰ� �����մϴ�.
			 1 - ����
	*/

	char base[100];				// ���ҵ� ���� ������
	char tmp[5];				// ���ҵ� ���ϵڿ� �ٴ� ����. ex) log1, log2, ...
	char analyzeFile[100];		// ������ ������ ���
	char newDirectory[100];		// ���ҵ� ������ write�ϱ� ���� ���ΰ��
	char filename[100] = "log";	// ���ҵ� ���� �̸�

	if (inputDir == NULL || baseDir == NULL)
		return 0; // ���������� �����մϴ�.

	strcpy(analyzeFile, inputDir);
	strcpy(base, baseDir);

	int file_counter = 0;
	int counter = 0;

	FILE* fp1;
	FILE* fp = fopen(analyzeFile, "r");
	if (fp == NULL)
		return -1; //������ ������ ��ΰ� �ùٸ��� �ʽ��ϴ�.

	_mkdir(base);


	while (!feof(fp)) {

		sprintf(tmp, "%d", file_counter);
		strcpy(newDirectory, base);		// "C:/Users/kimse/Desktop/pcaplog/"
		strcat(newDirectory, filename); // "C:/Users/kimse/Desktop/pcaplog/log"
		strcat(newDirectory, tmp);		// "C:/Users/kimse/Desktop/pcaplog/log0"
		file_counter++;

		fp1 = fopen(newDirectory, "a");
		if (fp == NULL)
			return -2; //���ҵ� �������� ��ΰ� �ùٸ��� �ʽ��ϴ�.

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


