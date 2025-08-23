#pragma once
#include <Windows.h>
#include <cstdint>

#define RESUME_TLS_CALLBACK (false)
#define IGNORE_TLS_CALLBACK (true)
#define ID_UPDATE_DR0 0
#define ID_UPDATE_DR1 1
#define ID_UPDATE_DR2 2
#define ID_UPDATE_DR3 3
#define ID_UPDATE_DR7 4

namespace ApiLoader
{
    enum BreakpointCondition : int32_t { Execute = 0, Write = 1, ReadWrite = 3 };

    typedef uintptr_t(__fastcall* t_icallback)(uintptr_t stack, int64_t is_hyperion, uintptr_t callee, uintptr_t rax);
    typedef int64_t(__fastcall* t_exception_handler)(PEXCEPTION_RECORD precord, PCONTEXT pctx);
    typedef bool (NTAPI* t_thread_init)(PCONTEXT start_context);
    typedef bool (NTAPI* t_user_tls_callback)(PVOID h, DWORD dwReason, PVOID pv, uintptr_t stack);
    typedef void(__fastcall* t_syscall_detour)(DWORD syscallId, PCONTEXT pctx);

	uintptr_t* fnlist = nullptr;
	uintptr_t* indata = nullptr;

	void init(void* a)
	{
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

    static inline void set_bits(unsigned long& dw, int lowBit, int bits, int newValue)
    {
        int mask = (1 << bits) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111
        dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
    }

    void set_breakpoint(int id, uintptr_t address, BreakpointCondition cd)
    {
        indata[20 + id] = address;

        //int when = (int)cd;
        //int len = 4;
        //int m_index = 0;
        //
        //unsigned long dr7 = 0;
        //set_bits(dr7, 16 + (m_index * 4), 2, when);
        //set_bits(dr7, 18 + (m_index * 4), 2, len);
        //set_bits(dr7, m_index * 2, 1, 1);
        //indata[24] = dr7;
        //
        //reinterpret_cast<void(__fastcall*)()>(fnlist[4])();
    }

    // Reset hardware breakpoint (index 0-4). Please note this wont reset changes to the Dr7 register...
    void reset_breakpoint(int id)
    {
        indata[20 + id] = indata[45 + id];

        //reinterpret_cast<void(__fastcall*)()>(fnlist[5])();
    }

    // Reset all breakpoints (including dr7)
    void reset_breakpoints()
    {
        indata[20 + 0] = indata[45 + 0];
        indata[20 + 1] = indata[45 + 1];
        indata[20 + 2] = indata[45 + 2];
        indata[20 + 3] = indata[45 + 3];
        indata[20 + 4] = indata[45 + 4];
        reinterpret_cast<void(__fastcall*)()>(fnlist[5])();
    }
}
