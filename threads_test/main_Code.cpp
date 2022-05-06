#include <stdio.h>
#include <Windows.h>
#include <direct.h>
#include "thread.h"

int main() {
	// 1. 파일정보를 확인한다.
	char fileDir[100] = "C:/Users/kimse/Desktop/테스트 폴더";
	char fileName[20] = "/result.txt";
	char folderName[10] = "result";
	_chdir(fileDir);

	printf("활동 경로 : %s", fileDir);
	printf("파일 이름 : %s", fileName);
	strcat(fileDir, fileName);

	printf("파일 경로 : %s", fileName);

	
	// 2. 특정 용량을 넘어가면 100mb 사이즈(약 100000줄) 단위로 파일을 분리한다.
	F_info* fileInfo;
	fileInfo = analyze_File(fileDir);

	
	// 3. 분리된 파일들의 갯수를 확인한 뒤, 스레드들을 호출
	
	// 4. 동시접근 리스트에 스레드 결과를 집어 넣는다.

	return 0;
}



