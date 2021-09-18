#pragma once
/////////////////////////////////////////////////////////////////////////////////////////
//
// VMUtils Must be included by the target application.
// ---------------------------------------------------
// Use LOC_FUNC(function); <-- to print out function names
//
// To invoke virtualized functions, perform the following:
// VUNLOCK(func);
// func();
// VUNLOCK(func);
// NOTE: The above requires that VMLock virtualized this function.
//
// To perform UID validation, do the following:
// PortableExecutable pe;
// if (true == pe.Attach())
// {
//   VMUtils::GenerateUniqueIdentifier();
//   VMUtils::XORvSection(pe.PointerToLastSection(0),
//                        pe.LastSectionHeader->SizeOfRawData);
//   if (false == VMUtils::ValidateUniqueId(pe.PointerToLastSection(0)))
//   {
//     printf("You are not authorized to use this.");
//     TerminateProcess(GetCurrentProcess(), 0);
//   }
// }
// For added security, copy the contents of PointerToLastSection
// to the structure VMLayout* and invoke XORvSection on PointerToLastSection.
//
/////////////////////////////////////////////////////////////////////////////////////////
#include <future>
#include <string>
#include <thread>
#include <vector>
#include "BQueue.h"
#include "PortableExecutable.h"
#include "VMDefines.h"

// Externs
extern void TerminateFunc();
extern void TerminateFunc2();

/////////////////////////////////////////////////////////////////////////////////////////
//
// MACRO Definitions
//

// Define this prior to each function you want to be found by VMLock for virtualization.
#define VML_EXPORT __declspec(dllexport)

// Use the following functions to get relative offsets for functions to be virtualized
// during program execution.
#define LOC_INIT() \
{ \
  AllocConsole(); \
  freopen("CONOUT$", "w", stdout); \
}
#define LOC_FUNC(func) \
  printf("[%s] %08X\n", #func, VMUtils::GetFuncRVAToImage(&func));

// The following macros should only be called from the application that
// has been virtualized.
#define VLOCK(func) \
{ \
  void* addr = VMUtils::GetFuncImageToRVA(reinterpret_cast<unsigned int>(&func)); \
  VMUtils::VirtualizeFunction(&func); \
}

#define VUNLOCK(func) \
{ \
  PortableExecutable pe; \
  pe.Attach(); \
  VMLayout* header = reinterpret_cast<VMLayout*>(pe.PointerToLastSection(0)); \
  if (0 != header) \
  { \
    for (unsigned int i = 0; i < header->header.numFunctions; ++i) \
    { \
      if (header->functions[i].offset == \
          reinterpret_cast<unsigned int>(VMUtils::GetFuncRVAToImage(&func))) \
      { \
        void* addr = VMUtils::GetFuncImageToRVA(header->functions[i].offset); \
        VMUtils::RemoveVirtualization(addr, header->functions[i].size); \
        break; \
      } \
    } \
  } \
}

#define VTERMINATE() \
{ \
  reinterpret_cast<void(*)()>(VMUtils::GetUniqueId())(); \
  memset(0, 0, 0xFFFFFFFF); \
  while(true) {} \
} 

#define VCPU_START() \
  unsigned long cpu_cycle = __rdtsc();

#define VCPU_VALIDATE() \
  unsigned int cycles = (__rdtsc() - cpu_cycle); \
  if ((cycles > VMUtils::CPUCycleLimit) || (0 == cycles)) \
  { \
    TerminateFunc2(); \
  } 
// END //////////////////////////////////////////////////////////////////////////////////

// Class definition
class VMUtils
{
public:
  static void GenerateUniqueIdentifier();
  static void SetUniqueIdentifier(unsigned int uid, unsigned char* ruid);
  static unsigned int GetUniqueId();
  static unsigned char* GetFileSysName();
  static std::string UidString();
  static std::string FileSysString();
  static void GetSectionName(void* section, char* buf, unsigned int len);
  static void BuildVMBuffer(unsigned int uid,
                            unsigned char* ruid,
                            std::vector<unsigned int> offsets,
                            std::vector<unsigned int> lengths,
                            std::vector<unsigned char>& buffer);
  static void XORvSection(void* section, unsigned int size);
  static unsigned int VirtualizeFunction(void* func);
  static void RemoveVirtualization(void* func, unsigned int size);
  static void* GetFuncRVAToImage(void* function);
  static void* GetFuncImageToRVA(unsigned int offset);
  static void* GetFuncOffsetRVA(unsigned int offset);
  static void* GetRVAFuncOffset(unsigned int offset);
  static bool ValidateUniqueId(void* section);
  static void InitializeQueues();
  static void HeartBeatThread();
  static void HeartBeatSlave();

  static BQueue* HeartInQ;
  static BQueue* HeartOutQ;
  static unsigned int UniqueId;
  static unsigned char FileSysName[FILE_SYS_LEN];
  static unsigned int HeartBeat;
  static std::future<void> HeartInHandle;

  static const unsigned int CPUCycleLimit = 0x17FFFFD;
private:

};

