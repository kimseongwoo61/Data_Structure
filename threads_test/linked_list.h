#pragma once
#include <stdio.h>
#include "pcapLog_parser.h"

typedef struct _parsing_Result { //�ؼ� ����� ����Ǵ� ��� ����ü
	pcapInfo* data;		  // ����� ������ ����ü(�����Ҵ��� ����ǹǷ� �����ͷ� �޴´�.)
	parsingResult* next;  // ���� ����� �ּ� ������
	parsingResult* prev;  // ���� ����� �ּ� ������
	_parsing_Result() {   // ������ - ������ ����� ��� null�� �ʱ�ȭ �Ѵ�.
		memset(this, 0x0, sizeof(struct _parsing_Result));
	}

}parsingResult;


void List_insert(pcapInfo* data); // ��带 Ư�� �ε����� �����Ѵ�.
void List_delete(parsingResult* input); // Ư�� �ε����� ��ġ�� ��带 �����Ѵ�.
int List_count(parsingResult* input);   // ����Ʈ�� ���� ������ ������ �ش�. -> ���� ����Ʈ���� �迭�� ��ȯ�� Ȱ�밡��
parsingResult* List_view(parsingResult* condition); // ���ǿ� �´� ����Ʈ �׸��� �˻��� �ش�.


