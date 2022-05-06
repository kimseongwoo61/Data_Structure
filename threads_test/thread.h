#pragma once
#include <stdio.h>
#include <Windows.h>
#include <process.h>
#include "file_Operation.h"
#include "linked_list.h"
#include "pattern.h"
#include "pcapLog_parser.h"

unsigned int __stdcall ThreadFunc(void*);
int read_thread();
HANDLE hMutex;
