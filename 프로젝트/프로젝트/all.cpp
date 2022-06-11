#include "all.h"
#include <time.h>

parsingResult* firstNode;
CRITICAL_SECTION cs;
HANDLE hthread[1000];

parsingResult* List_create() {
	parsingResult* node = (parsingResult*)malloc(sizeof(parsingResult));
	return node;
}

void List_insert(parsingResult** target, parsingResult* newNode) {
	EnterCriticalSection(&cs);
	if (target == NULL)
		*target = newNode;
	else {
		parsingResult* tail = *target;
		while (tail->next != NULL) tail = tail->next;
		tail->next = newNode;
	}
	LeaveCriticalSection(&cs);
	return;
}

void List_delete(parsingResult* head) {
	parsingResult* tmp_front = head;
	parsingResult* tmp_back = head->next;

	while (true) {
		if (tmp_front == NULL)
			break;
		printf("Ȯ�ε� ����Ʈ�� ����մϴ�.\n");
		printf(" - %s\n", tmp_front->data.seqNum);
		printf(" - %s\n", tmp_front->data.time);
		printf(" - %s\n", tmp_front->data.sendAddr);
		printf(" - %s\n", tmp_front->data.recvAddr);
		printf(" - %s\n", tmp_front->data.protocol);
		printf(" - %s\n", tmp_front->data.option);
		free(tmp_front);
		tmp_front = tmp_back;
		tmp_back = tmp_back->next;
	}
}

int List_count(parsingResult* target) {
	int counter = 0;
	parsingResult* tmp = target;

	while (true) {
		if (target == NULL)
			break;
		counter++;
		tmp = target->next;
	}
	return counter;
}

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


unsigned int getLine_Count(FILE* fp) {
	int lineCounter = 0;
	char lastWord;

	while ((lastWord = fgetc(fp)) != EOF) {
		if (lastWord == '\n')
			lineCounter++;
	}
	return lineCounter;
}


unsigned int getFile_Size(FILE* fp) {
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
			//printf("%c", tmp_chr);
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


void logScaner(char* getLine, pcapInfo* output) {
	char* ptr;
	int count = 1;
	ptr = strtok(getLine, " ");
	strcpy(output->seqNum, ptr);    //������ȣ ����

	ptr = strtok(NULL, " ");        //�ð����� ����
	strcpy(output->time, ptr);

	ptr = strtok(NULL, " ");
	strcpy(output->sendAddr, ptr);  //�۽��� ip ���� ����

	ptr = strtok(NULL, " ");
	strcpy(output->recvAddr, ptr);  //������ ip ���� ����

	ptr = strtok(NULL, " ");
	strcpy(output->protocol, ptr); //�������� ���� ����

	ptr = strtok(NULL, "\n");
	strcpy(output->option, ptr); //�������� ���� 
}

int landAttack(pcapInfo* checker) {
	if (!strcmp(checker->recvAddr, checker->sendAddr))
		return 1;
	else
		return NULL;
}


int suspicious_syn_Flood(pcapInfo* checker) {
	char option[4] = "SYN";
	if (!strcmp(checker->protocol, "TCP")) {
		if (strstr(checker->option,"ACK") != NULL)
			return 1;
	}
	return NULL;
}


int suspicious_Smurf(char* brocastAddr, pcapInfo* checker) { //brocast_Addr = 192.168.0.
	if (!strcmp(checker->protocol, "ICMP") && strstr(checker->sendAddr, brocastAddr))
		return 1;
	else
		return NULL;
}






parsingResult* GetfileList(char* path, char* search_point) {
	intptr_t h_file;
	char search_Path[100];
	file_parsing* info = NULL;
	FILE_SEARCH file_search;
	int index = 0;
	firstNode = (parsingResult*)malloc(sizeof(parsingResult));
	firstNode->next = NULL;
	
	InitializeCriticalSection(&cs);
	sprintf_s(search_Path, "%s/*.*", path);
	
	

	if ((h_file = _findfirst(search_Path, &file_search)) == -1) {
		printf("No files in current directory!\n");
		return NULL;
	}

	else {
		do {
			if (!strcmp(file_search.name, "..") || !strcmp(file_search.name, "."))
				continue;

			readThread(path, file_search, search_point, index++);
			//WaitForMultipleObjects(index, hthread, TRUE, INFINITE);
		} while (_findnext(h_file, &file_search) == 0);
		_findclose(h_file);
	}
	WaitForMultipleObjects(index, hthread, TRUE, INFINITE);
	for (int i = 0; i < index; i++)
		CloseHandle(hthread[i]);

	DeleteCriticalSection(&cs);
	return firstNode;
}




void readThread(char* path, FILE_SEARCH file_search, char* search_point, int index) {
	char fullDir[200];

	strcpy(fullDir, path);
	strcat(fullDir, file_search.name);
	

	file_parsing* data;
	data = (file_parsing*)malloc(sizeof(file_parsing));

	strcpy(data->fullDirectory, fullDir);
	strcpy(data->search_type, search_point);

	printf("\n\n �����带 �����մϴ�.\n");
	
	hthread[index] = (HANDLE)_beginthreadex(NULL, 0, Thread_R, (void*)data, 0, NULL);
	//Thread_R((void*)data);
		
	if (hthread[index] == NULL) {
		printf("error!!!");
	}
	//WaitForSingleObjectEx(hthread[index], INFINITE,TRUE);
	//WaitForMultipleObjects(index, hthread, TRUE, INFINITE);
	//for (int i = 0; i < 1000; i++)
		//CloseHandle(hthread[i]);
	return;
}


unsigned int __stdcall Thread_R(void* lpParam) {
	file_parsing* data = (file_parsing*)lpParam;
	FILE* fp = NULL;
	char line[1001];


	pcapInfo* testCase;
	fp = fopen(data->fullDirectory, "r");
	int i = 0;
	if (fgets(line, sizeof(line), fp) == NULL) {
		printf("1����\n");
		fclose(fp);
		return 0;
	}
	
	while (!feof(fp)) {
		testCase = (pcapInfo*)malloc(sizeof(pcapInfo));
		//printf("%s\n", line);
		
		logScaner(line, testCase);
		/*if (strstr(data->search_type, "Land_Attack") && landAttack(testCase)) {
			List_insert(lastNode, testCase);
		}*/
		
		if (strstr(data->search_type, "suspicious_syn_Flood") != NULL && suspicious_syn_Flood(testCase)){
			parsingResult* newNode = (parsingResult*)malloc(sizeof(parsingResult));
			printf("�߰��մϴ�.\n");
			strcpy(newNode->data.option, testCase->option);
			strcpy(newNode->data.protocol, testCase->protocol);
			strcpy(newNode->data.recvAddr, testCase->recvAddr);
			strcpy(newNode->data.sendAddr, testCase->sendAddr);
			strcpy(newNode->data.seqNum, testCase->seqNum);
			strcpy(newNode->data.time, testCase->time);
			newNode->next = NULL;
			List_insert(&firstNode, newNode);
		}
		else {
			free(testCase);
		}

			

		/*if (!strcmp(data->search_type, "suspicious_Smurf")) {
			if (strcmp(data->broadcast_Addr, "asdf") && suspicious_Smurf(data->broadcast_Addr, testCase))
				List_insert(lastNode, testCase);
		}*/
		if (fgets(line, sizeof(line), fp) == NULL) {
			printf("2����\n");
			fclose(fp);
			return 0;
		}
	}
	
	fclose(fp);
	printf("�����带 �����մϴ�.\n");
	
	return 0;
}


