#include <stdio.h>
#include <Windows.h>
#include <direct.h>
#include "thread.h"

int main() {
	// 1. ���������� Ȯ���Ѵ�.
	char fileDir[100] = "C:/Users/kimse/Desktop/�׽�Ʈ ����";
	char fileName[20] = "/result.txt";
	char folderName[10] = "result";
	_chdir(fileDir);

	printf("Ȱ�� ��� : %s", fileDir);
	printf("���� �̸� : %s", fileName);
	strcat(fileDir, fileName);

	printf("���� ��� : %s", fileName);

	
	// 2. Ư�� �뷮�� �Ѿ�� 100mb ������(�� 100000��) ������ ������ �и��Ѵ�.
	F_info* fileInfo;
	fileInfo = analyze_File(fileDir);

	
	// 3. �и��� ���ϵ��� ������ Ȯ���� ��, ��������� ȣ��
	
	// 4. �������� ����Ʈ�� ������ ����� ���� �ִ´�.

	return 0;
}



