#include "stdafx.h"

int main() {
	printf("[!] Open driver connection: ");
	if (driver->Init(FALSE)) {
		printf("Success!\n");
		driver->Attach(L"explorer.exe");
		while (true)
		{
			clock_t begin = clock();
			auto module = driver->GetModuleBase(L"explorer.exe");
			clock_t end = clock();
			double time_spent = (double)(end - begin);
			printf("Request took: %f | %fs\n", time_spent, time_spent / CLOCKS_PER_SEC);
			printf("base.addr: 0x%llX\n", module.addr);
			printf("base.size: 0x%llX\n", module.size);
			Sleep(2000);
		}
		return 0;
	}
	printf("Failed!\n");
	system("pause");
	return 1;
}