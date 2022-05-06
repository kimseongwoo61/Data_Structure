#pragma once
#include <stdio.h>
#include <string.h>
#include "pcapLog_parser.h"
#include "linked_list.h"
#include "pattern.h"


int MACHING_COUNTER = 0; //��Ī�Ǵ� ����� ī��Ʈ �ϴ� ����������, ��� ����Ʈ��

pcapInfo* landAttack(pcapInfo* checker);					// �ۼ������� IP ������ ��ġ�ϸ� count���� �ø��� �ش� ����ü ������ �����Ѵ�.
pcapInfo* suspicious_TCP_syn_Flood(pcapInfo* checker);      // tcp ���������� ack �÷��׸� �����Ͽ� ������ ��� ������ ��� �˻�
pcapInfo* suspicious_Smurf(pcapInfo* checker);
