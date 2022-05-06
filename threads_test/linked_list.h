#pragma once
#include <stdio.h>
#include "pcapLog_parser.h"

typedef struct _parsing_Result { //해석 결과가 저장되는 노드 구조체
	pcapInfo* data;		  // 저장될 데이터 구조체(동적할당이 진행되므로 포인터로 받는다.)
	parsingResult* next;  // 다음 노드의 주소 포인터
	parsingResult* prev;  // 이전 노드의 주소 포인터
	_parsing_Result() {   // 생성자 - 각각의 멤버들 모두 null로 초기화 한다.
		memset(this, 0x0, sizeof(struct _parsing_Result));
	}

}parsingResult;


void List_insert(pcapInfo* data); // 노드를 특정 인덱스에 삽입한다.
void List_delete(parsingResult* input); // 특정 인덱스에 위치한 노드를 삭제한다.
int List_count(parsingResult* input);   // 리스트의 원소 개수를 리턴해 준다. -> 추후 리스트에서 배열로 변환시 활용가능
parsingResult* List_view(parsingResult* condition); // 조건에 맞는 리스트 항목을 검색해 준다.


