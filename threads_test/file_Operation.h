#pragma once
#include <stdio.h>
#include <stdlib.h>


// �������� : ������, ���� ��
typedef struct File_information {
	unsigned int fileSize;
	unsigned int fileRow;
}F_info;


// ���� ���ұ�� ���� �Լ�
void analyze_File(char* fileDirectory, F_info* attrbute); //�м� ������ ������� ���μ��� ����ü�� �����Ѵ�.
unsigned int getLine_Count(FILE* fp);					  //������ ���μ��� ��ȯ�Ѵ�.
unsigned int getFile_Size(FILE* fp);					  //������ �뷮������ ��ȯ�Ѵ�. 
int fileSpliter(char* inputDir, char* baseDir, int line);  //���� ��ο� ���� ����������, ������ �ټ��� �Է¹޾� �����۾��� �����Ѵ�.
