#include <Windows.h>
#include <string>
#include <stdio.h>
#include <codecvt>
#include <iostream>
#include <iomanip>

#include <TlHelp32.h>

/*
	This is exclusively made for certain process.
*/

class Decoder {
private:
	HANDLE hProcess = {};
	DWORD processId = 0;
	
	uintptr_t baseAddress = 0;
	uintptr_t opCode1 = 0x1990; // Offset of the jnz where the yes or no compare happens.

public:
	auto ReadOpcodes(uintptr_t address, int numBytes) {
		unsigned char* buffer = new unsigned char[numBytes]; // buffer -> hold the bytes of readprocessmemory or the return value
		SIZE_T bytesRead = 0; // bytesRead -> hold the number of bytes actually read

		if (!ReadProcessMemory(this->hProcess, (LPVOID)address, buffer, numBytes, &bytesRead)) {
			std::cerr << "ReadProcessMemory failed. Error: " << GetLastError() << "\n";
			delete[] buffer;
			exit(1);
		}

		std::cout << "Opcodes at 0x" << std::hex << address << ": ";
		for (SIZE_T i = 0; i < bytesRead; i++) {
			std::cout << std::setw(2) << std::setfill('0')
				<< (int)buffer[i] << " ";
		}
		std::cout << std::dec << std::endl;
		return buffer;
	}

	auto WriteOpcodes(uintptr_t address, unsigned char* opcodes, int numBytes) {
		SIZE_T bytesWritten = 0;
		if(!WriteProcessMemory(this->hProcess, (LPVOID)address, opcodes, numBytes, &bytesWritten)) {
			std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << "\n";
			exit(1);
		}

		ReadOpcodes(address, numBytes);
	}

	void getProcessId(std::wstring exeName) {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(pe32);

		if (Process32First(hSnap, &pe32)) {
			do {
				if (wcscmp(pe32.szExeFile, exeName.c_str()) == 0) {
					printf("Found process %ls with PID %lu\n", pe32.szExeFile, pe32.th32ProcessID);
					this->processId = pe32.th32ProcessID;
					this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->processId);
					CloseHandle(hSnap);
					return;
				}
			} while (Process32Next(hSnap, &pe32));
		}

		printf("Process %ls not found.\n", exeName.c_str());
		CloseHandle(hSnap);
		exit(1);
	}

	void getBaseAddress() {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->processId);
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(me32);

		if (Module32First(hSnap, &me32)) {
			this->baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
			printf("Base Address: 0x%p\n", (void*)this->baseAddress);
			return;
		}
		
		printf("Module not found for PID %lu.\n", this->processId);
		CloseHandle(hSnap);
		CloseHandle(this->hProcess);
		exit(1);
	}

	Decoder(std::wstring exeName) {
		getProcessId(exeName);
		getBaseAddress();

		auto targetOpcode = this->baseAddress + this->opCode1;
		auto read1 = ReadOpcodes(targetOpcode, 16);
		read1[10] = 0x90; // NOP the JNZ
		read1[11] = 0x90; // NOP the JNZ

		WriteOpcodes(targetOpcode, read1, 16);

	}

	~Decoder() {
		CloseHandle(this->hProcess);
	}
};

void createProcess() {

	// Get process path
	wchar_t fileName[MAX_PATH] = L"";
	OPENFILENAME openFileName = {};
	openFileName.lStructSize = sizeof(openFileName);
	openFileName.hwndOwner = NULL;
	openFileName.nMaxFile = MAX_PATH;
	openFileName.nFilterIndex = 1;

	openFileName.lpstrTitle = L"Select Executable to Decode";
	openFileName.lpstrFilter = L"Executable Files\0*.exe\0";
	openFileName.lpstrFile = fileName;
	openFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	if (!GetOpenFileName(&openFileName)) {
		printf("No file selected.\n");
		system("pause");
		exit(1);
	}

	// Get the exename
	std::wstring exeName(fileName);
	exeName = exeName.substr(exeName.find_last_of(L"\\", exeName.length()) + 1);
	wprintf(L"Executable Name: %s\n", exeName.c_str());

	// Create the process
	STARTUPINFO startupInfo = {};
	startupInfo.cb = sizeof(startupInfo);

	PROCESS_INFORMATION processInfo = {};
	BOOL result = CreateProcess(
		fileName,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE, // Create a new console window for the process
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	);
	if (!result) {
		printf("Failed to create process. Error code: %lu\n", GetLastError());
		system("pause");
		exit(1);
	}
	// Cleanup handles
	CloseHandle(&startupInfo);
	CloseHandle(&processInfo.hThread);

	// Decode the process
	Decoder decoder(exeName);
	
}

int main() {
	createProcess();
}