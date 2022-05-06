#include "thread.h"


unsigned int __stdcall ThreadFunc(void* arg) {
    // Mytex가 signal일때까지 기다리고 누군가
    // signal인 순간에는 non-signal로 바뀐다.
    // 스레드 인자 : arg* argu = (arg*)lParam;
    // 인자 정보 : 리스트 삽입을 위한 시작 주소, 검색 옵션.


    for (int i = 0; i < 2; i++) {
        // 파일 입출력 담당 부분.
        // 리스트 원소를 생성하는 부분.


        WaitForSingleObject(hMutex, INFINITE);
        // 힙 영역에 생성된 원소를 리스트에 연결하는 코드

        ReleaseMutex(hMutex); // signal로 만든다
    }
    return 0;
}


int thread_Setting() {
    HANDLE hMutex;
    HANDLE hThread[50];
    unsigned int dwThreadID[50];

    // 락(뮤텍스) 값 초기화
	hMutex = CreateMutex(NULL, FALSE, NULL); 

    // 파일 내용 패턴 매칭을 위한 스레드 생성
    for (int i = 0; i < 50; i++)
        hThread[i] = (HANDLE)_beginthreadex(
            NULL,
            0,
            ThreadFunc,
            NULL,//(void*)&input,
            CREATE_SUSPENDED,
            &dwThreadID[i]);

    //스케줄러에 쓰레드가 레디가 된것을 통보한다.
    for (int i = 0; i < 50; i++)
        ResumeThread(hThread[i]);

    //스레드가 종료되기 전까지 main 코드를 대기함.
    WaitForMultipleObjects(50, hThread, TRUE, INFINITE);

    // 모든 스레드들의 핸들을 정리
    for (int i = 0; i < 50; i++)
        CloseHandle(hThread[i]);

    // 뮤텍스도 모두 정리.
    CloseHandle(hMutex);
}