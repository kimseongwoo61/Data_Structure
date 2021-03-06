# Tshark log parser (based in thread list!!!)

# 프로젝트 기능 명세서 v0.1

# 목차

### **1장. API 목록**

- **1.1 개요
1.2 API 구성
1.3 의존 라이브러리
1.4 라이브러리 내부 코드 관리 구조**

### 2장. API 명세

- **2.1 구조체 및 전역변수
2.2 파일 관리
2.3 리스트
2.4 스레드
2.5 패턴 검색**

### 3장. 테스트 코드

- **3.1 테스트 코드 소스
3.2 테스트 결과
3.3 주의 사항**

### 4장. 기타정보

- **4.1 깃허브 주소**

# 1장 API 목록

## 1.1 개요

본 문서는 **Distributed Log Parsing Library**(이하 로그해석 라이브러리)에서 제공하는 API 명세를 기술합니다.

Tshark 로그 파일을 기반으로 동작되므로 해당 라이브러리 활용에 참고하시길 바랍니다.

## 1.2 API 구성

해당 라이브러리는 다양한 기능의 API를 제공하고 있습니다.

| 기능 | Function name | Parameter | Return value | Etc. |
| --- | --- | --- | --- | --- |
| File operation | analyze_File | char* fileDirectory, 
F_info* attrbute | void |  |
|  | getLine_Count | FILE* fp | unsigned int |  |
|  | getFile_Size | FILE* fp | unsigned int |  |
|  | fileSpliter | char* inputDir, char* baseDir, int line | int |  |
| Data structure - List | List_create | void | parsingResult*  |  |
|  | List_insert | parsingResult** target, parsingResult* newNode | void  |  |
|  | List_delete | parsingResult* target | void |  |
|  | List_count | parsingResult* target | int |  |
| Read file Thread | readThread | char* path, 
FILE_SEARCH file_search, char* search_point, int index | file_parsing* |  |
|  | GetfileList | char* path, 
char* search_point | parsingResult*  |  |
|  | Thread_R | void* lpParam | unsigned int | 호출규약 : __stdcall |
| Searching pattern | logScaner(); | char* getLine,
pcapInfo* output | void |  |
|  | landAttack | pcapInfo* checker | int |  |
|  | suspicious_syn_Flood | pcapInfo* checker | int |  |
|  | suspicious_Smurf | char* brocastAddr, pcapInfo* checker | int |  |

## 1.3 의존 라이브러리

해당 파싱 라이브러리는 외부의 서드파티를 사용하지 않으며 C언어, 윈도우에서 활용 가능한 라이브러리만을 활용합니다.

아래는 활용 라이브러리 목록입니다.

<direct.h>, <io.h>, <process.h> , <stdio.h>, <stdlib.h>, <string.h>, <time.h>, <Windows.>, <sys/types.h> : 

## 1.4 라이브러리 내부 코드관리 구조

all.h : 스레드 기반 리스트 및 검색 함수의 정의와 표준 c라이브러리

all.cpp : 라이브러리의 함수 원형이 저장되어 있는 소스 파일 입니다.

testcode.cpp : 라이브러리의 정상 작동을 확인하는 테스트 코드가 저장되어 있는 테스트 코드 파일 입니다.

![Untitled](Tshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled.png)

# 2장 API 명세

## 2.1 구조체 및 전역변수

```c
extern HANDLE hthread[1000];
extern CRITICAL_SECTION cs;
extern parsingResult* firstNode;
```

**hthread** : 스레드의 핸들을 저장하는 전역 배열로 처리 응답 시간을 설정 및 종료 처리를 위해 사용됩니다.

**cs** : 멀티 스레드 기반의 리스트 연산을 진행할 경우 내부 링크의 동시 접근으로 인한 오류가 발생할 가능성이 있습니다. 링크를 연결하는 부분의 스레드 진입을 통제하기 위한 임계영역 설정을 위해 사용되는 변수 입니다 

**firstNode** : 리스트의 시작 주소를 담고있는 포인터 변수로 스레드 들의 삽입 연산을 위해 사용됩니다.

```c
typedef struct pcapText_Line { 
	char seqNum[10];
	char time[20];
	char sendAddr[20];
	char recvAddr[20];
	char protocol[20];
	char option[200];
}pcapInfo;

typedef struct _parsingResult { 
	pcapInfo data;	
	struct _parsingResult* next;
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

typedef struct _finddata_t FILE_SEARCH;
```

**pcapText_Line**  : tshark 로그 텍스트의 파싱 결과를 저장하는 구조체 입니다.

tshark 리턴 형식 :

 ____[패킷 순서번호]_[시간정보]_[송신지ip]_→_[수신지ip]_[프로토콜 종류]_[그외 각각의 프로토콜 추가 정보]

(_ : 공백(Blank))

- time : 패킷이 기록된 시간 정보를 저장하는 멤버입니다.
- seqNum : 기록된 패킷의 순서를 저장하는 멤버입니다.
- sendAddr : 송신지 ip 정보를 저장하는 멤버 입니다.
- recvAddr : 수신지 ip 정보를 저장하는 멤버 입니다.
- protocol : 통신에 사용된 프로토콜의 정보를 저장하는 멤버 입니다.
- option : 기타 프로토콜의 부가적인 정보(flag, other info, …)를 저장하는 멤버 입니다.

**parsingResult** : tshark 로그 텍스트의 파싱 결과를 리스트 형태로 저장하기 위한 노드 구조체 입니다.

- data : tshark 로그 파싱 결과를 저장하는 멤버 입니다.
- next : 다음 노드를 가리키는 포인터 멤버입니다.

**arg** : 스레드의 인자를 넘기기 위한 구조체 입니다.

- fullDirectory : 스레드가 읽을 파일경로를 저장하는 멤버 입니다.
- search_type : 로그 파일로 부터 검출할 패턴의 종류를 저장하는 멤버입니다.
- broadcast_Addr : 브로드 캐스트 주소를 저장하는 멤버 변수로 suspicious_Smurf에 활용됩니다.
- Node : 검출 패턴을 삽입할 노드의 주소를 저장하는 멤버 입니다.

## 2.2 파일 관리

```c
void analyze_File(char* fileDirectory, F_info* attrbute); 
unsigned int getLine_Count(FILE* fp);					 
unsigned int getFile_Size(FILE* fp);					 
int fileSpliter(char* inputDir, char* baseDir, int line); 
```

**void analyze_File(char* fileDirectory, F_info* attrbute);**

- 매개변수 정보
    
    char* fileDirectory : 분석할 파일의 절대 경로
    
    F_info* attrbute : 파일 속성을 저장할 F_info 구조체 포인터 변수
    
- 기능 설명
    
    입력된 경로에 위치하는 파일의 텍스트 줄 수와 사이즈 정보를 파싱 후 attrbute 포인터 인자에 저장한다.
    
- 리턴 값 : void

**unsigned int getLine_Count(FILE* fp);**

- 매개변수 정보
FILE* fp : 분석할 파일의 파일 파일 포인터
- 기능설명
입력된 파일 포인터를 통해 텍스트 파일 내부 줄수를 int 형으로 반환해줍니다.
- 리턴값 : 텍스트 파일 줄 수(int)

**unsigned int getFile_Size(FILE* fp);**

- 매개변수 정보
FILE* fp : 분석할 파일의 파일 파일 포인터
- 기능설명
입력된 파일 포인터를 통해 파일 사이즈를 측정해 줍니다.
- 리턴값 : 파일 크기(int)

**int fileSpliter(char* inputDir, char* baseDir, int line);**

- 매개변수 정보
char* inputDir : 분할할 tshark 로그 텍스트 파일이 위치한 경로 문자열 포인터 입니다.
char* baseDir : 파일을 분할할 경로 문자열 포인터 입니다.
int line : 텍스트 파일을 분할할 줄의 수를 저장한 정수값 인자 입니다.
- 기능설명
입력된 파일 정보를 통해 분할할 줄 수 만큼 파일을 분할하여 baseDir 경로에 저장해 줍니다.
- 리턴값 : int
    - 상세 정보
    파일 분할 성공 시 : 1
    Error number :
        - 분할할 파일의 경로가 올바르지 않습니다. : -1
        - 분할된 파일의 경로가 올바르지 않습니다. : -2
        - 알 수 없는 에러가 발생하였습니다. : -3
        - 인자가 부족합니다. : 0

## 2.3 리스트

```c
parsingResult* List_create();
void List_insert(parsingResult** target, parsingResult* newNode);
void List_delete(parsingResult* target);
int List_count(parsingResult* target);
```

**parsingResult* List_create();**

- 매개변수 정보 : void
- 기능설명
parsingResult 구조체를 동적 할당 후 관리를 위한 구조체 포인터를 반환합니다.
- 리턴값 : parsingResult*

**void List_insert(parsingResult** target, parsingResult* newNode);**

- 매개변수 정보
parsingResult** target : 리스트의 시작 주소 입니다.
parsingResult* newNode : 리스트에 삽입할 노드 포인터 입니다.
- 기능설명
리스트에 newNode를 삽입해주는 함수 입니다.
- 리턴값 : void
****

**void List_delete(parsingResult* target);**

- 매개변수 정보
parsingResult* target : 삭제할 리스트의 시작 주소 입니다.
- 기능설명
리스트 내부의 동적 할당되어 있는 노드들을 모두 해제해주는 함수 입니다.
- 리턴값 : void
****

**int List_count(parsingResult* target);**

- 매개변수 정보
parsingResult* target : 리스트의 시작주소 입니다.
- 기능설명
리스트의 시작주소로 부터 다음 주소가 NULL 일때까지 노드수를 카운트하여 반환해 줍니다.
- 리턴값 : 전체 노드수(int)

## 2.4 스레드

```c
void readThread(char* path, FILE_SEARCH file_search, char* search_point, int index);
parsingResult* GetfileList(char* path, char* search_point);
unsigned int __stdcall Thread_R(void* lpParam);
```

**void readThread(char* path, FILE_SEARCH file_search, char* search_point, int index);**

- 매개변수 정보
char* path : 분할된 파일의 절대 경로 입니다.
FILE_SEARCH file_search : 분할된 파일의 정보를 저장하고 있는 FILE_SEARCH 구조체 변수 입니다.
char* search_point : 검색할 공격 패턴을 지정한 문자열 입니다.
    - 지정 옵션
    - “Land_attack” : 송수신 ip 주소가 같은 로그를 검색합니다.
    - “suspicious_syn_Flood” : TCP 통신에서 SYN 플래그 통신을 검색합니다.
    - “suspicious_Smurf” : 브로드 캐스트 주소로 icmp 프로토콜 통신 기록을 검색합니다.
    
    int index : 파일 파싱을 위해 생성된 스레드를 관리하기 위한 스레드 핸들 배열의 인덱스 입니다.
    
- 기능설명
분할된 파일을 입력된 검색 옵션에 맟춰 검색을 진행하는 스레드를 호출해주는 함수 입니다.
- 리턴값 : void
****

**parsingResult* GetfileList(char* path, char* search_point);** 

- 매개변수 정보
char* path : 분할된 파일이 존재하는 절대경로 정보 입니다.
char* search_point : 스레드를 통해 검색할 옵션이며, readThread의 옵션과 동일합니다.
- 기능설명
분할된 파일을 순차적으로 스레드를 호출하여 Dos 공격 패턴을 검색해주는 함수 입니다.
- 리턴값 : 검색 결과가 저장된 리스트의 시작주소의 포인터(**parsingResult***)

**unsigned int __stdcall Thread_R(void* lpParam);**

- 매개변수 정보
void* lpParam : 스레드에 들어갈 인자입니다.
각각의 넘길 수 있는 인자 항목은 상단의 구조체 arg 부분을 참고해 주세요.
- 기능설명
지정한 검색옵션을 기반으로 패턴을 찾아 리스트에 삽입해주는 함수 입니다.
- 리턴값 : void

## 2.5 패턴 검색

```c
void logScaner(char* getLine, pcapInfo* output);    
int landAttack(pcapInfo* checker);					
int suspicious_syn_Flood(pcapInfo* checker);    
int suspicious_Smurf(char* brocastAddr, pcapInfo* checker);
```

**void logScaner(char* getLine, pcapInfo* output);**

- 매개변수 정보
char* getLine : tshark log 텍스트 파일로 부터 읽은 한줄의 로그를 저장하고 있는 버퍼의 주소 입니다.
pcapInfo* output : 파싱 결과를 저장할 pcapInfo 구조체의 주소 입니다.
- 기능설명
tshark log를 읽고 해당 결과를 반환해 줍니다.
tshark 리턴 형식 :
    
     ____[패킷 순서번호]_[시간정보]_[송신지ip]_→_[수신지ip]_[프로토콜 종류]_[그외 각각의 프로토콜 추가 정보]
    
    (_ : 공백(Blank))
    
- 리턴값 : void

**int landAttack(pcapInfo* checker);**

- 매개변수 정보
pcapInfo* checker : 텍스트 로그로부터 파싱된 결과를 저장하고있는 pcapInfo 구조체 변수의 주소입니다.
- 기능설명 
pcapInfo 구조체를 통해 송수신 IP 정보가 일치하는 패킷 정보를 검색하는 함수 입니다.
- 리턴값
    - 일치 : 1(int)
    없음 : NULL

**int suspicious_syn_Flood(pcapInfo* checker);**

- 매개변수 정보
pcapInfo* checker : 텍스트 로그로부터 파싱된 결과를 저장하고있는 pcapInfo 구조체 변수의 주소입니다.
- 기능설명
pcapInfo 구조체를 통해 TCP 프로토콜로 SYN 플래그가 on되어 있는 패킷을 검사합니다.
- 리턴값
    - 일치 : 1(int)
    없음 : NULL

**int suspicious_Smurf(char* brocastAddr, pcapInfo* checker);**

- 매개변수 정보
char* brocastAddr : 서버상의 브로드케스트 주소 정보입니다. 
pcapInfo* checker : 텍스트 로그로부터 파싱된 결과를 저장하고있는 pcapInfo 구조체 변수의 주소입니다.
- 기능설명
pcapInfo 구조체를 통해 브로드 캐스트 주소로 ICMP 프로토콜 통신 기록을 검사합니다.
- 리턴값
    - 일치 : 1(int)
    없음 : NULL
    

# 3장 테스트 코드

## 3.1 테스트 코드 소스

```c
#include "all.h"
#include <time.h>
void Analyzing(char* analysisFile, char* temp, char* dosSignature);

int main() {
	// 파일 경로
	// 저장 경로
	// 분석 항목
	// 리스트 받아오기
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
	printf(" 다중 스레드 기반 소요된 시간 : %.3f \n", res1);
	//DeleteCriticalSection(&cs);

	return 0;
}

void Analyzing(char* analysisFile, char* temp, char* dosSignature) {	
	// 파일 분할

	//int line = getLine_Count()
	if (fileSpliter(analysisFile, temp, 5) != 1) {
		printf("분할에 실패했습니다.");
		return;
	}
	parsingResult* test = GetfileList(temp, dosSignature);
	parsingResult* temps = test;
	temps = temps->next;

	printf("마지막 ---------------\n");
	while (1) {
		printf("%s %s\n", temps->data.seqNum, temps->data.recvAddr);
		temps = temps->next;
		if (temps == NULL)
			break;
	}
	
}
```

## 3.2 테스트 결과

```c
		1   0.000000 64.233.189.188 172.30.1.26  TCP 66 443 58964 [ACK] Seq=1 Ack=1 Win=265 Len=0 SLE=0 SRE=1
    2   0.266836  172.30.1.26 34.64.4.10   UDP 75 53615 443 Len=33
    3   0.300480   34.64.4.10 172.30.1.26  UDP 67 443 53615 Len=25
    4   5.836485  172.30.1.26 13.225.125.157 TCP 54 58935 80 [FIN, ACK] Seq=1 Ack=1 Win=517 Len=0
    5   5.844743 13.225.125.157 172.30.1.26  TCP 54 80 58935 [FIN, ACK] Seq=1 Ack=2 Win=131 Len=0
    6   5.844818  172.30.1.26 13.225.125.157 TCP 54 58935 80 [ACK] Seq=2 Ack=2 Win=517 Len=0
    4   5.836485  172.30.1.26 13.225.125.157 TCP 54 58935 80 [FIN, ACK] Seq=1 Ack=1 Win=517 Len=0
    5   5.844743 13.225.125.157 172.30.1.26  TCP 54 80 58935 [FIN, ACK] Seq=1 Ack=2 Win=131 Len=0
    6   5.844818  172.30.1.26 13.225.125.157 TCP 54 58935 80 [ACK] Seq=2 Ack=2 Win=517 Len=0
    6   5.844818  172.30.1.26 13.225.125.157 TCP 54 58935 80 [ACK] Seq=2 Ack=2 Win=517 Len=0
-----
```

### (**좌 - 스레드 기반 동작, 우 - 단일 프로세스 기반의 동작)**

![Untitled](Tshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%201.png)

![Untitled](Tshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%202.png)

![Untitled](Tshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%203.png)

해당 테스트 부분을 통해 단일 프로세스 기반의 리스트 연산보다 스레드 기반의 검색이 보다 빠른 결과 리턴이 가능함을 알 수 있습니다.

## 3.3 주의사항

1) 리스트 결과
- 리스트 결과는 스레드 기반으로 검색 및 삽입된 것이기에 별도의 정렬을 진행하지 않습니다.

2) 리스트 연산
- 리스트 삽입 연산을 제외하고는 스레드 기능을 제공하지 않습니다.

3) tshark 로그 포맷 문제
- 원본 텍스트 로그를 ASCII로 읽기 때문에 ‘→’ 문자가 정상적으로 읽히지 않습니다.
- 만약 해당 라이브러리를 사용할 경우 ‘→’ 문자만 삭제한 후 진행해주시길 바랍니다.

4) 스레드 및 파일 분할
- 코드 설계상 분할된 파일 마다 각각의 파싱을 위한 스레드가 호출됩니다.
- 통상 스레드 호출 개수가 3개를 넘어갈 경우 심각한 성능저하를 유발할 수 있으므로 파일 분할을 
  위한 라인수를 지정할 시 참고하시길 바랍니다. 

## 4장 기타 정보

### 4.1 깃허브 주소 :

- [https://github.com/kimseongwoo61/Data_Structure/tree/main](https://github.com/kimseongwoo61/Data_Structure/tree/main)