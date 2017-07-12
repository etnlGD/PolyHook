#ifndef POLYHOOK_TOOL_H
#define POLYHOOK_TOOL_H
#include <windows.h>
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <utility>
#include <TlHelp32.h>
#include <assert.h>
#include <memory>
#define PLH_SHOW_DEBUG_MESSAGES 1 //To print messages even in release
#if _MSC_VER <= 1800
#define noexcept
#define USE_DEFAULT
#else
#define USE_DEFAULT =default
#endif

namespace PLH {
	namespace Tools
	{
		inline void XTrace(char* fmt, ...)
		{
			va_list args;
			va_start(args, fmt);
#if defined(_DEBUG) || defined(PLH_SHOW_DEBUG_MESSAGES)
			vfprintf_s(stdout, fmt, args);
#endif
			va_end(args);
		}

		class ThreadHandle
		{
		public:
			//Thread ID, OpenThread's AccessFlag 
			ThreadHandle(DWORD ThreadId, DWORD  DesiredAccessFlags) : m_ThreadId(ThreadId), m_IsSuspended(false)
			{
				m_hThread = OpenThread(DesiredAccessFlags, FALSE, ThreadId);
				if (m_hThread == NULL)
					throw "PolyHook: Failed to open thread in class ThreadHandle";
			}

			//Only allow once instance to control a handle
			ThreadHandle(const ThreadHandle& other) = delete; //copy
			ThreadHandle& operator=(const ThreadHandle& other) = delete; //copy assignment

			//Move
			ThreadHandle(ThreadHandle &&other) noexcept
				: m_IsSuspended(other.m_IsSuspended)
				, m_hThread(other.m_hThread)
				, m_ThreadId(other.m_ThreadId)
			{
				other.m_hThread = nullptr;
				other.m_IsSuspended = false;
			}

			//Move assignment
			ThreadHandle& operator=(ThreadHandle &&other) noexcept
			{
				if (this != &other)
				{
					m_IsSuspended = other.m_IsSuspended;
					m_hThread = other.m_hThread;
					m_ThreadId = other.m_ThreadId;

					other.m_hThread = nullptr;
					other.m_IsSuspended = false;
				}
				return *this;
			}


				//false resumes, true suspends
				void ToggleSuspend(bool Suspend)
			{
				if (Suspend && !m_IsSuspended)
				{
					if (SuspendThread(m_hThread) != -1)
						m_IsSuspended = true;
				}
				else if (!Suspend && m_IsSuspended){
					if (ResumeThread(m_hThread) != -1)
						m_IsSuspended = false;
				}
			}

			~ThreadHandle()
			{
				if (m_IsSuspended)
					ToggleSuspend(false);

				if (m_hThread)
					CloseHandle(m_hThread);
			}
		private:
			bool m_IsSuspended;
			HANDLE m_hThread;
			DWORD m_ThreadId;
		};

		class ThreadManager
		{
		public:
			void SuspendThreads()
			{
				UpdateThreadList(GetCurrentThreadId());
				for (ThreadHandle& ThreadInstance : m_SuspendedThreads)
				{
					ThreadInstance.ToggleSuspend(true);
				}
			}

			void ResumeThreads()
			{
				for (ThreadHandle& ThreadInstance : m_SuspendedThreads)
				{
					ThreadInstance.ToggleSuspend(false);
				}
			}
		private:
			void UpdateThreadList(DWORD CallingThreadId)
			{
				m_SuspendedThreads.clear();
				HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
				if (h == INVALID_HANDLE_VALUE)
					return;

				THREADENTRY32 te;
				te.dwSize = sizeof(te);
				BOOL Result = FALSE;
				//Loop threads
				for (Result = Thread32First(h, &te), te.dwSize = sizeof(te); Result == TRUE && Thread32Next(h, &te);)
				{
					//Verify size field was set properly
					if (te.dwSize < RTL_SIZEOF_THROUGH_FIELD(THREADENTRY32, th32OwnerProcessID))
						continue;

					if (te.th32ThreadID != CallingThreadId && te.th32OwnerProcessID == GetCurrentProcessId())
						m_SuspendedThreads.emplace_back(te.th32ThreadID, THREAD_SUSPEND_RESUME);
				}
				CloseHandle(h);
			}
			std::vector<Tools::ThreadHandle> m_SuspendedThreads;
		};

		inline void* Allocate_2GB_IMPL(uint8_t* pStart, size_t Size, int_fast64_t Delta)
		{
			/*These lambda's let us use a single for loop for both the forward and backward loop conditions.
			I passed delta variable as a parameter instead of capturing it because it is faster, it allows
			the compiler to optimize the lambda into a function pointer rather than constructing
			an anonymous class and incur the extra overhead that involves (negligible overhead but why not optimize)*/
			auto Incrementor = [](int_fast64_t Delta, MEMORY_BASIC_INFORMATION& mbi) -> uintptr_t{
				if (Delta > 0)
					return (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
				else
					return (uintptr_t)mbi.BaseAddress - 1; //TO-DO can likely jump much more than 1 byte, figure out what the max is
			};

			auto Comparator = [](long long int Delta, uintptr_t Addr, uintptr_t End)->bool {
				if (Delta > 0)
					return Addr < End;
				else
					return Addr > End;
			};

			//Start at pStart, search 2GB around it (up/down depending on Delta)
			MEMORY_BASIC_INFORMATION mbi;
			for (uintptr_t Addr = (uintptr_t)pStart; Comparator(Delta, Addr, (uintptr_t)pStart + Delta); Addr = Incrementor(Delta, mbi))
			{
				if (!VirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
					break;

				assert(mbi.RegionSize != 0);

				if (mbi.State != MEM_FREE)
					continue;

				//VirtualAlloc requires 64k aligned addresses
				void* PageBase = (uint8_t*)mbi.BaseAddress - LOWORD(mbi.BaseAddress);
				if (void* Allocated = (uint8_t*)VirtualAlloc(PageBase, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
					return Allocated;
			}
			return nullptr;
		}

		inline void* AllocateWithin2GB(uint8_t* pStart, size_t Size, size_t& AllocationDelta)
		{
			static const size_t MaxAllocationDelta = 0x80000000; //2GB

			//Attempt to allocate +-2GB from pStart
			AllocationDelta = 0;
			void* Allocated = nullptr;
			Allocated = Tools::Allocate_2GB_IMPL(pStart, Size, (~MaxAllocationDelta) + 1); //Search down first (-2GB) 

			//If search down found nothing
			if (Allocated == nullptr)
				Allocated = Tools::Allocate_2GB_IMPL(pStart, Size, MaxAllocationDelta); //Search up (+2GB)

			//Sanity check the delta is less than 2GB
			if (Allocated != nullptr)
			{
				AllocationDelta = std::abs(pStart - (uint8_t*)Allocated);
				if (AllocationDelta > MaxAllocationDelta)
				{
					//Out of range, free then return
					VirtualFree(Allocated, 0, MEM_RELEASE);
					return nullptr;
				}
			}
			return Allocated;
		}
	}
}

#endif//end include guard
