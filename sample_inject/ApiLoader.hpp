#pragma once
#include <Windows.h>
#include <cstdint>
#include <fstream>
#include <vector>
#include <unordered_map>

#define RESUME_TLS_CALLBACK (false)
#define IGNORE_TLS_CALLBACK (true)
#define ID_UPDATE_DR0 0
#define ID_UPDATE_DR1 1
#define ID_UPDATE_DR2 2
#define ID_UPDATE_DR3 3
#define ID_UPDATE_DR7 4
#define DLL_THREAD_UPDATE 0x1000


#pragma warning (disable:6385)

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

namespace ApiLoader
{
    enum BreakpointCondition : int32_t { Execute = 0, Write = 1, ReadWrite = 3 };

    typedef uintptr_t(__fastcall* t_icallback)(uintptr_t stack, int64_t is_hyperion, uintptr_t callee, uintptr_t rax);
    typedef uint64_t(__fastcall* t_exception_handler)(PEXCEPTION_RECORD precord, PCONTEXT pctx);
    typedef bool (NTAPI* t_thread_init)(PCONTEXT start_context);
    typedef bool (NTAPI* t_user_tls_callback)(PVOID h, DWORD dwReason, PVOID pv, uintptr_t stack);
    typedef void(__fastcall* t_syscall_detour)(DWORD syscallId, PCONTEXT pctx);

	std::vector<std::pair<std::string, std::uintptr_t>>safe_loaded_imports = {};
    uintptr_t dlls_start = 0;
	uintptr_t* fnlist = nullptr;
	uintptr_t* indata = nullptr;

	void init(void* a)
	{
        dlls_start = reinterpret_cast<uintptr_t>(a) + (0x08000000 - 0x100000);
        indata = reinterpret_cast<uintptr_t*>(a);
        fnlist = reinterpret_cast<uintptr_t*>(&indata[54]);
	}

    void set_instrumentation_callback(t_icallback f)
    {
        fnlist[0] = reinterpret_cast<uintptr_t>(f);
    }

    void set_exception_handler(t_exception_handler f)
    {
        fnlist[1] = reinterpret_cast<uintptr_t>(f);
    }

    void set_thread_init(t_thread_init f)
    {
        fnlist[2] = reinterpret_cast<uintptr_t>(f);
    }

    void set_tls_callback(t_user_tls_callback f)
    {
        fnlist[3] = reinterpret_cast<uintptr_t>(f);
    }

    void set_syscall_detour(t_syscall_detour f)
    {
        fnlist[6] = reinterpret_cast<uintptr_t>(f);
    }

    inline void set_bits(unsigned long* dw, int lowBit, int bits, int newValue)
    {
        int mask = (1 << bits) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111
        *dw = (*dw & ~(mask << lowBit)) | (newValue << lowBit);
    }

    void set_breakpoint(int id, uintptr_t address, BreakpointCondition cd)
    {
        indata[20 + id] = address;

        int when = static_cast<int>(cd);
        int len = 1;
        int m_index = id;
        
        unsigned long dr7 = indata[24];
        set_bits(&dr7, 16 + (m_index * 4), 2, when);
        //set_bits(&dr7, 18 + (m_index * 4), 2, len);
        //set_bits(&dr7, m_index * 2, 1, 1);
        indata[24] = dr7;
        
        reinterpret_cast<void(__fastcall*)()>(fnlist[4])();
    }

    // Reset hardware breakpoint (index 0-4). Please note this wont reset changes to the Dr7 register...
    void reset_breakpoint(int id)
    {
        indata[20 + id] = indata[45 + id];

        int when = (int)BreakpointCondition::Execute;
        int len = 1;
        int m_index = id;

        unsigned long dr7 = indata[24];
        set_bits(&dr7, 16 + (m_index * 4), 2, when);
        //set_bits(&dr7, 18 + (m_index * 4), 2, len);
        //set_bits(&dr7, m_index * 2, 1, 1);
        indata[24] = dr7;

        reinterpret_cast<void(__fastcall*)()>(fnlist[4])();
    }

    // Reset all breakpoints (including dr7)
    void reset_breakpoints()
    {
        //indata[20 + 0] = indata[45 + 0];
        //indata[20 + 1] = indata[45 + 1];
        //indata[20 + 2] = indata[45 + 2];
        //indata[20 + 3] = indata[45 + 3];
        //indata[20 + 4] = indata[45 + 4];
        //reinterpret_cast<void(__fastcall*)()>(fnlist[4])();
        reinterpret_cast<void(__fastcall*)()>(fnlist[5])();
    }

    HMODULE load_dll(const wchar_t* szDllFile, std::uintptr_t* entry_point = nullptr, bool load_entry_point = true, bool load_tls_callbacks = true)
    {
        uintptr_t target_base = dlls_start;
		size_t total_size = 0x1000;

		BYTE* pSrcData = nullptr;
		IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;

		using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

		//struct MANUAL_MAPPING_DATA
		//{
		//	BYTE* pbase;
		//	HINSTANCE			hMod;
		//};

		std::fstream out = std::fstream("C:/Users/Javan/Desktop/CeleryDebug.txt", std::ios::out | std::ios::app);
		//out << "Loading dll at " << std::hex << target_base << std::endl;

		if (GetFileAttributesW(szDllFile) == INVALID_FILE_ATTRIBUTES)
		{
			out.close();
			return NULL;
		}

		std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

		if (File.fail()) {
			File.close();
			out.close();
			return NULL;
		}

		auto FileSize = File.tellg();
		if (FileSize < 0x1000) {
			File.close();
			out.close();
			return NULL;
		}

		pSrcData = new BYTE[(UINT_PTR)FileSize];
		if (!pSrcData) {
			File.close();
			out.close();
			return NULL;
		}

		File.seekg(0, std::ios::beg);
		File.read(reinterpret_cast<char*>(pSrcData), FileSize);
		File.close();

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
			delete[] pSrcData;
			out.close();
			return NULL;
		}

		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		pOldOptHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		if (pOldFileHeader->Machine != CURRENT_ARCH)
		{
			delete[] pSrcData;
			out.close();
			return NULL;
		}

		//printf("File image size: %08X\n", pOldOptHeader->SizeOfImage);

		//const auto pShellcode = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		auto pTargetBase = reinterpret_cast<BYTE*>(target_base);// VirtualAlloc(nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if (!pTargetBase)
		{
			delete[] pSrcData;
			out.close();
			return NULL;
		}

		//MANUAL_MAPPING_DATA data{ 0 };
		//data.pbase = pTargetBase;

		//out << "Writing dll header" << std::endl;

		//File header
		memcpy(pTargetBase, pSrcData, 0x1000);

		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->SizeOfRawData) {
				
				//out << "Mapping section " << reinterpret_cast<const char*>(pSectionHeader->Name) << " at " << std::hex << reinterpret_cast<uintptr_t>(pTargetBase + pSectionHeader->VirtualAddress) << std::endl;
				
				memcpy(pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
				
				const auto section_end = pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData;
				if (section_end > total_size)
					total_size = section_end;
			}
		}

		//Mapping params
		//BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(/*MemUtil::virtualAlloc(sizeof(MANUAL_MAPPING_DATA), PAGE_READWRITE));*/ VirtualAlloc(nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT, PAGE_READWRITE));
		//if (!MappingDataAlloc) {
		//	//printf("Target process mapping allocation failed (ex) 0x%X\n", GetLastError());
		//	delete[] pSrcData;
		//	return 0;
		//}


		// ####################################################################
		// Data directory pointers...To make this injection 100x easier,
		// we will just load all of the target processes libraries into
		// ours to get the function offsets.locally with GetProcAddress.
		// They will share the same memory across processes.
		// 
		//auto pBase = new uint8_t[pOldOptHeader->SizeOfImage];
		//SIZE_T nbytes;
		//ReadProcessMemory(GetCurrentProcess(), pTargetBase, pBase, pOldOptHeader->SizeOfImage, &nbytes);
		//if (pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		//{
		//	auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		//	while (pImportDescr->Name)
		//	{
		//		char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
		//
		//		HINSTANCE hDll = LoadLibraryA(szMod);
		//		if (hDll)
		//		{
		//			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
		//			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);
		//
		//			if (!pThunkRef)
		//				pThunkRef = pFuncRef;
		//
		//			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
		//			{
		//				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
		//				{
		//					//printf("Import name: %s\n", reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
		//					*pFuncRef = (ULONG_PTR)GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
		//				}
		//				else
		//				{
		//					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
		//					//printf("Import name: %s\n", pImport->Name);
		//					*pFuncRef = (ULONG_PTR)GetProcAddress(hDll, pImport->Name);
		//				}
		//
		//				//printf("Import: %p\n", *pFuncRef);
		//			}
		//		}
		//
		//		++pImportDescr;
		//	}
		//}
		//WriteProcessMemory(GetCurrentProcess(), pTargetBase, pBase, pOldOptHeader->SizeOfImage, &nbytes);
		//delete[] pBase;
		// ####################################################################
		const auto dll_size = pOldOptHeader->SizeOfImage;

		//if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		//	//printf("Can't write mapping 0x%X\n", GetLastError());
		//	delete[] pSrcData;
		//	return false;
		//}

		delete[] pSrcData;


		auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pTargetBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pTargetBase)->e_lfanew)->OptionalHeader;
		auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pTargetBase + pOpt->AddressOfEntryPoint);

		if (entry_point)
			*entry_point = reinterpret_cast<uintptr_t>(_DllMain);

		BYTE* LocationDelta = pTargetBase - pOpt->ImageBase;
		if (LocationDelta)
		{
			//out << "Relocating w/ location delta " << std::hex << reinterpret_cast<uintptr_t>(LocationDelta) << "..." << std::endl;
			
			if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			{

			}
			else
			{
				auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pTargetBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
				while (pRelocData->VirtualAddress)
				{
					UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

					for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
					{
						if (RELOC_FLAG(*pRelativeInfo))
						{
							UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pTargetBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
							*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
						}
					}
					pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
				}
			}
		}

		auto nimports = (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (nimports > 0 && nimports < 0x100)
		{
			//out << "Updating imports...Size: " << pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size << std::endl;
			
			auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pTargetBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			
			auto nimport = 0;
			while (nimport + 1 < nimports)
			{
				if (!pImportDescr->Name)
				{
					out << "Skipping import " << nimport << " of " << nimports << ". Import name: (UNRESOLVED)" << std::endl;
					++pImportDescr;
					nimport++;
					continue;
				}

				char* szMod = reinterpret_cast<char*>(pTargetBase + pImportDescr->Name);

				for (auto i = 0; i < strlen(szMod); i++)
					szMod[i] = std::tolower(szMod[i]);

				out << "Resolving import " << nimport << " of " << nimports << ". Import name: " << szMod << std::endl;

				//out << "Found import: " << szMod << std::endl;
				
				/*
				append_file(DEBUG_OUT_PATH, szMod);

				HINSTANCE hDll = nullptr;

				struct MODULE_ENTRY
				{
					char name[0x30];
					uintptr_t pointer;
				};

				for (size_t i = 0; i < modules_count; i++)
				{
					append_file(DEBUG_OUT_PATH, reinterpret_cast<MODULE_ENTRY*>(modules_list)[i].name);

					bool match = true;
					for (size_t j = 0; j < 0x30; j++)
					{
						char c = reinterpret_cast<MODULE_ENTRY*>(modules_list)[i].name[j];
						if (c == '\0')
							break;
						if (szMod[j] != c)
						{
							match = false;
							break;
						}
					}
					if (match)
					{
						hDll = reinterpret_cast<HMODULE>(reinterpret_cast<MODULE_ENTRY*>(modules_list)[i].pointer);
					}
				}
				*/

				int nresults = 0;

				HMODULE hDll;

				// If the import dll name starts with "api-ms-win-core-",
				// the function might actually be in kernelbase.dll.
				// Check if we mapped our own kernelbase, and retrieve
				// the exported functions from there.
				// Current limitation: 
				// In this case, we assume all the exported functions
				// will match up with the kernelbase that we mapped.
				// What I could do is search the remaining unfound
				// functions in the real import dll (szMod)
				if (strncmp(szMod, "api-ms-win-", sizeof("api-ms-win-") - 1) == 0)
				{
					const char* szModTry = const_cast<char*>("kernelbase.dll\0");
					bool is_safe_import = false;

					for (const auto& imp : safe_loaded_imports)
					{
						if (strncmp(imp.first.c_str(), szModTry, strlen(szModTry)) == 0)
						{
							//out << "Using safely mapped import '" << imp.first << "'" << std::endl;

							hDll = reinterpret_cast<HMODULE>(imp.second);

							is_safe_import = true;
							break;
						}
					}

					if (is_safe_import)
					{
						ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pTargetBase + pImportDescr->OriginalFirstThunk);
						ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pTargetBase + pImportDescr->FirstThunk);

						if (!pThunkRef)
							pThunkRef = pFuncRef;

						constexpr const auto MAX_SYMNAME_LEN = 128;

						auto pBaseOther = reinterpret_cast<BYTE*>(hDll);

						UINT32* export_addr_table = nullptr;
						UINT32* export_nameptr_table = nullptr;
						UINT16* export_ordinal_table = nullptr;
						IMAGE_EXPORT_DIRECTORY* exp = nullptr;
						std::unordered_map<UINT32, UINT32> ordinals_map = {};

						auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBaseOther + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBaseOther)->e_lfanew)->OptionalHeader;

						exp = (IMAGE_EXPORT_DIRECTORY*)(pBaseOther + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

						//out << "Searching in protected import" << std::endl;

						export_addr_table = (UINT32*)(pBaseOther + exp->AddressOfFunctions);
						export_nameptr_table = (UINT32*)(pBaseOther + exp->AddressOfNames);
						export_ordinal_table = (UINT16*)(pBaseOther + exp->AddressOfNameOrdinals);

						// Make a map to quickly pull up the real index
						for (SIZE_T j = 0; j < exp->NumberOfNames; j++)
						{
							ordinals_map[export_ordinal_table[j]] = j;
						}

						bool found = false;

						for (int nthunks = 0; *pThunkRef; ++pThunkRef, ++pFuncRef, ++nthunks)
						{
							char* symbolName;

							if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
							{
								symbolName = const_cast<char*>("(null)");//itoa(static_cast<int>(*pThunkRef & 0xFFFF), nullptr, 10); // reinterpret_cast<char*>(*pThunkRef & 0xFFFF)

								out << "Got image snap by ordinal: " << static_cast<int>(*pThunkRef & 0xFFFF) << "." << std::endl;
							}
							else
							{
								auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pTargetBase + (*pThunkRef));
								symbolName = pImport->Name;
							}

							out << "[" << nthunks << "] Searching for function name '" << symbolName << "'" << " in import dll '" << szModTry << "'" << std::endl;

							for (SIZE_T i = 0; i < exp->NumberOfFunctions && !found; i++)
							{
								UINT32 ordinal = exp->Base + i;
								UINT32 export_rva = export_addr_table[i];

								//if (is_forwarder_rva(export_rva))
								//{
								//	// TODO: special care must be taken here - we cannot resolve directly to a VA unless target module is memory mapped
								//}
								//else
								{
									BOOL found_symname = FALSE;
									char symname[MAX_SYMNAME_LEN];

									// Loop through all exported names
									//for (SIZE_T j = 0; j < exp->NumberOfNames; j++)
									//{
									//	if (export_ordinal_table[j] == i)
									//	{
									SIZE_T j = ordinals_map[i];
									UINT32 export_symname_rva = export_nameptr_table[j];

									const char* export_symname = (const char*)(pBaseOther + export_symname_rva);

									std::string str1(symbolName), str2(export_symname);

									if (strncmp(symbolName, export_symname, strlen(symbolName)) == 0)
									{
										found_symname = TRUE;
										found = true;
										*pFuncRef = reinterpret_cast<uintptr_t>(pBaseOther + export_rva);

										break;
									}
									//	}
									//}
								}
							}

							if (!found)
							{
								out << "Function '" << symbolName << "' not found in module " << std::hex << hDll << std::endl;
							}
						}

						if (found)
						{
							// Continue looking through import dlls
							++pImportDescr;
							++nimport;
							continue;
						}
					}
				}

				bool is_safe_import = false;

				for (const auto& imp : safe_loaded_imports)
				{
					if (strncmp(imp.first.c_str(), szMod, strlen(szMod)) == 0)
					{
						//out << "Using safely mapped import '" << imp.first << "'" << std::endl;
						
						hDll = reinterpret_cast<HMODULE>(imp.second);

						is_safe_import = true;
						break;
					}
				}

				if (!is_safe_import)
					hDll = GetModuleHandleA(szMod);

				if (!hDll)
				{
					out << "Loading unimported library '" << szMod << "'. If the dll is not a system library, it might be blacklisted." << std::endl;
					hDll = LoadLibraryA(szMod);
				}

				if (!hDll)
				{
					out << "Failed to fetch library '" << szMod << "'." << std::endl;
					continue;
				}
				else
				{
					ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pTargetBase + pImportDescr->OriginalFirstThunk);
					ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pTargetBase + pImportDescr->FirstThunk);

					if (!pThunkRef)
						pThunkRef = pFuncRef;

					constexpr const auto MAX_SYMNAME_LEN = 128;

					auto pBaseOther = reinterpret_cast<BYTE*>(hDll);

					UINT32* export_addr_table = nullptr;
					UINT32* export_nameptr_table = nullptr;
					UINT16* export_ordinal_table = nullptr;
					IMAGE_EXPORT_DIRECTORY* exp = nullptr;
					std::unordered_map<UINT32, UINT32> ordinals_map = {};

					if (is_safe_import)
					{
						auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBaseOther + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBaseOther)->e_lfanew)->OptionalHeader;

						exp = (IMAGE_EXPORT_DIRECTORY*)(pBaseOther + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

						//out << "Searching in protected import" << std::endl;

						export_addr_table = (UINT32*)(pBaseOther + exp->AddressOfFunctions);
						export_nameptr_table = (UINT32*)(pBaseOther + exp->AddressOfNames);
						export_ordinal_table = (UINT16*)(pBaseOther + exp->AddressOfNameOrdinals);

						// Make a map to quickly pull up the real index
						for (SIZE_T j = 0; j < exp->NumberOfNames; j++)
						{
							ordinals_map[export_ordinal_table[j]] = j;
						}
					}

					for (int nthunks = 0; *pThunkRef; ++pThunkRef, ++pFuncRef, ++nthunks)
					{
						bool found = false;
						char* symbolName;

						if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
						{
							symbolName = const_cast<char*>("(null)");//itoa(static_cast<int>(*pThunkRef & 0xFFFF), nullptr, 10); // reinterpret_cast<char*>(*pThunkRef & 0xFFFF)
						
							out << "Got image snap by ordinal: " << static_cast<int>(*pThunkRef & 0xFFFF) << "." << std::endl;
						}
						else
						{
							auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pTargetBase + (*pThunkRef));
							symbolName = pImport->Name;
						}

						out << "[" << nthunks << "] Searching for function name '" << symbolName << "'" << " in import dll '" << szMod << "'" << std::endl;
						
						if (is_safe_import)
						{
							for (SIZE_T i = 0; i < exp->NumberOfFunctions && !found; i++)
							{
								UINT32 ordinal = exp->Base + i;
								UINT32 export_rva = export_addr_table[i];
							
								//if (is_forwarder_rva(export_rva))
								//{
								//	// TODO: special care must be taken here - we cannot resolve directly to a VA unless target module is memory mapped
								//}
								//else
								{
									BOOL found_symname = FALSE;
									char symname[MAX_SYMNAME_LEN];
									
									// Loop through all exported names
									//for (SIZE_T j = 0; j < exp->NumberOfNames; j++)
									//{
									//	if (export_ordinal_table[j] == i)
									//	{
									SIZE_T j = ordinals_map[i];
									UINT32 export_symname_rva = export_nameptr_table[j];

									const char* export_symname = (const char*)(pBaseOther + export_symname_rva);
									
									std::string str1(symbolName), str2(export_symname);

									if (strncmp(symbolName, export_symname, strlen(symbolName)) == 0)
									{
										found_symname = TRUE;
										found = true;
										*pFuncRef = reinterpret_cast<uintptr_t>(pBaseOther + export_rva);

										break;
									}
									//	}
									//}
								}
							}
							
							if (!found)
							{
								out << "Function '" << symbolName << "' not found" << std::endl;
							}
						}
						else
						{
							*pFuncRef = (ULONG_PTR)GetProcAddress(hDll, symbolName);
						}
					}
				}

				//out << "Finished resolving import " << (nimport - 1) << " of " << pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size << "." << std::endl;
				
				++pImportDescr;
				++nimport;
			}

		}

		if (load_tls_callbacks)
		{
			if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
			{
				//out << "Calling tls callbacks" << std::endl;
				
				auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pTargetBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
				auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
				for (; pCallback && *pCallback; ++pCallback)
					(*pCallback)(pTargetBase, DLL_THREAD_ATTACH, nullptr);
			}
		}

		if (load_entry_point)
		{
			_DllMain(reinterpret_cast<HMODULE>(pTargetBase), DLL_THREAD_ATTACH, nullptr);
		}

		if (total_size > dll_size)
			dlls_start += total_size + 0x1000;
		else
			dlls_start += dll_size + 0x1000;

		char dll_name[128];

		std::size_t i = 0, lastp = 0;
		while (i < lstrlenW(szDllFile))
		{
			if (szDllFile[i] == '/' || szDllFile[i] == '\\')
				lastp = i + 1;
			i++;
		}

		for (i = 0; i < 128; i++)
		{
			if (szDllFile[lastp + i] == 0)
			{
				dll_name[i] = '\0';
				break;
			}
			else
				dll_name[i] = std::tolower(static_cast<char>(szDllFile[lastp + i]));
		}

		out << "Added " << dll_name << " (at " << std::hex << target_base << ", file size: " << std::hex << dll_size  << ", total size: " << std::hex << total_size << ") to registry" << std::endl;
		safe_loaded_imports.push_back({ std::string(dll_name), target_base });

		out.close();
        return reinterpret_cast<HMODULE>(target_base);
    }

	std::uintptr_t get_export(HMODULE target_base, const char* symbol_name)
	{
		auto pBase = reinterpret_cast<BYTE*>(target_base);
		auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;
		
		IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(pBase
			+ pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		constexpr const auto MAX_SYMNAME_LEN = 64;

		UINT32* export_addr_table = (UINT32*)(pBase + exp->AddressOfFunctions);
		UINT32* export_nameptr_table = (UINT32*)(pBase + exp->AddressOfNames);
		UINT16* export_ordinal_table = (UINT16*)(pBase + exp->AddressOfNameOrdinals);

		for (SIZE_T i = 0; i < exp->NumberOfFunctions; i++)
		{
			UINT32 ordinal = exp->Base + i;
			UINT32 export_rva = export_addr_table[i];

			//if (is_forwarder_rva(export_rva))
			//{
			//	// TODO: special care must be taken here - we cannot resolve directly to a VA unless target module is memory mapped
			//}
			//else
			{
				BOOL found_symname = FALSE;
				char symname[MAX_SYMNAME_LEN];

				// Loop through all exported names
				for (SIZE_T j = 0; j < exp->NumberOfNames; j++)
				{
					if (export_ordinal_table[j] == i)
					{
						UINT32 export_symname_rva = export_nameptr_table[j];
						const char* export_symname = (const char*)(pBase + export_symname_rva);
						found_symname = TRUE;

						std::string str1(symbol_name), str2(export_symname);

						if (str1 == str2)
						{
							return reinterpret_cast<uintptr_t>(pBase + export_rva);
						}
					}
				}
			}
		}

		return 0;
	}
}
