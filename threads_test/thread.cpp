#include "thread.h"


unsigned int __stdcall ThreadFunc(void* arg) {
    // Mytex�� signal�϶����� ��ٸ��� ������
    // signal�� �������� non-signal�� �ٲ��.
    // ������ ���� : arg* argu = (arg*)lParam;
    // ���� ���� : ����Ʈ ������ ���� ���� �ּ�, �˻� �ɼ�.


    for (int i = 0; i < 2; i++) {
        // ���� ����� ��� �κ�.
        // ����Ʈ ���Ҹ� �����ϴ� �κ�.


        WaitForSingleObject(hMutex, INFINITE);
        // �� ������ ������ ���Ҹ� ����Ʈ�� �����ϴ� �ڵ�

        ReleaseMutex(hMutex); // signal�� �����
    }
    return 0;
}


int thread_Setting() {
    HANDLE hMutex;
    HANDLE hThread[50];
    unsigned int dwThreadID[50];

    // ��(���ؽ�) �� �ʱ�ȭ
	hMutex = CreateMutex(NULL, FALSE, NULL); 

    // ���� ���� ���� ��Ī�� ���� ������ ����
    for (int i = 0; i < 50; i++)
        hThread[i] = (HANDLE)_beginthreadex(
            NULL,
            0,
            ThreadFunc,
            NULL,//(void*)&input,
            CREATE_SUSPENDED,
            &dwThreadID[i]);

    //�����ٷ��� �����尡 ���� �Ȱ��� �뺸�Ѵ�.
    for (int i = 0; i < 50; i++)
        ResumeThread(hThread[i]);

    //�����尡 ����Ǳ� ������ main �ڵ带 �����.
    WaitForMultipleObjects(50, hThread, TRUE, INFINITE);

    // ��� ��������� �ڵ��� ����
    for (int i = 0; i < 50; i++)
        CloseHandle(hThread[i]);

    // ���ؽ��� ��� ����.
    CloseHandle(hMutex);
}