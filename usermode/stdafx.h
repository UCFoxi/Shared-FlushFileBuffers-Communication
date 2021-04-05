#pragma once
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <ntstatus.h>
#include <atomic>
#include <mutex>
#include <TlHelp32.h>

#include "utils.h"
#include "driver.h"

#pragma comment(lib, "ntdll.lib")