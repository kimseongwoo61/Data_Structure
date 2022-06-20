#include "all.h"
#include <time.h>
void Analyzing(char* analysisFile, char* temp, char* dosSignature);

int main() {
	// ���� ���
	// ���� ���
	// �м� �׸�
	// ����Ʈ �޾ƿ���
	clock_t start1, end1;
	float res1;

	char analysisFile[300] = "C:/Users/kimse/Desktop/text.txt";
	char temp[300] = "C:/Users/kimse/Desktop/temp/";
	char dosSignature[300] = "suspicious_syn_Flood";

	//InitializeCriticalSection(&cs);
	start1 = clock();
	Analyzing(analysisFile, temp, dosSignature);
	end1 = clock();
	res1 = (float)(end1 - start1) / CLOCKS_PER_SEC;
	printf(" ���� ���μ��� �ҿ�� �ð� : %.3f \n", res1);
	//DeleteCriticalSection(&cs);


	return 0;
}

void Analyzing(char* analysisFile, char* temp, char* dosSignature) {	
	// ���� ����

	//int line = getLine_Count()
	if (fileSpliter(analysisFile, temp, 1000) != 1) {
		printf("���ҿ� �����߽��ϴ�.");
		return;
	}
	parsingResult* test = GetfileList(temp, dosSignature);
	parsingResult* temps = test;
	temps = temps->next;

	printf("������ ---------------\n");
	while (1) {
		printf("%s %s\n", temps->data.seqNum, temps->data.recvAddr);
		temps = temps->next;
		if (temps == NULL)
			break;
	}
	
}