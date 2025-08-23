// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ApiLoader.hpp"
#include <cstdint>
#include <stdio.h>
#include <fstream>

// Custom TLS callback!
bool on_tls_callback(PVOID h, DWORD reason, PVOID pv, uintptr_t)
{
    MessageBoxA(0, "TLS CALLBACK FIRED!", "", MB_OK);

    return RESUME_TLS_CALLBACK;
}

std::uintptr_t module_base;

// Detour for every hyperion syscall (pre-IC) (excluded in this release)
void on_syscall(DWORD syscallId, PCONTEXT pctx)
{
    std::fstream out("C:/syscalls.txt", std::ios::out);
    if (out.is_open())
    {
        out << "Syscall at " << std::hex << pctx->Rip << ". ID: " << std::hex << syscallId << ".";
        out.close();
    }
}

// Custom exception handler!
int64_t on_exception(PEXCEPTION_RECORD precord, PCONTEXT pctx)
{
    // Only handle exceptions occurring from this DLL
    if (reinterpret_cast<std::uintptr_t>(precord->ExceptionAddress) < module_base || reinterpret_cast<std::uintptr_t>(precord->ExceptionAddress) > module_base + 0x10000000)
        return EXCEPTION_CONTINUE_SEARCH;

    switch (precord->ExceptionCode)
    {
    case EXCEPTION_BREAKPOINT:
    {
        ApiLoader::set_exception_handler(nullptr); // remove our exception handler

        char msg[128];
        sprintf(msg, "Exception occurred at %p!", precord->ExceptionAddress);
        MessageBoxA(0, msg, "Exception", MB_OK);

        pctx->Rip += 1; // Skip our __debugbreak()

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    case EXCEPTION_SINGLE_STEP:
    {
        //// Reset hardware breakpoint (at index 0)
        //ApiLoader::reset_breakpoint(0);
        //
        //char msg[128];
        //sprintf(msg, "Hardware breakpoint occurred at %p!", precord->ExceptionAddress);
        //MessageBoxA(0, msg, "Exception", MB_OK);
        //
        //return EXCEPTION_CONTINUE_EXECUTION;
    }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void load_exploit(std::uintptr_t dll_base)
{
    module_base = dll_base;

    //ApiLoader::set_syscall_detour(on_syscall);

    // Uncomment to demonstrate custom tls callback:
    //ApiLoader::set_tls_callback(on_tls_callback);

    // Uncomment to demonstrate custom exception handling:
    //ApiLoader::set_exception_handler(on_exception);
    //__debugbreak();

    // Not included in this release \/
    // Uncomment to demonstrate hardware breakpoints:
    //ApiLoader::set_exception_handler(on_exception);
    //ApiLoader::set_breakpoint(0, 0x7FFE0308, ApiLoader::BreakpointCondition::ReadWrite);

    MessageBoxA(0, "Injected!", "", MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Load runtime libraries for most C++ features
        LoadLibraryA("MSVCP140.dll");
        LoadLibraryA("VCRUNTIME140.dll");
        LoadLibraryA("VCRUNTIME140_1.dll");

        // Initialize the api :)
        ApiLoader::init(lpReserved);

        // Load the exploit
        load_exploit(reinterpret_cast<std::uintptr_t>(hModule));

        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

