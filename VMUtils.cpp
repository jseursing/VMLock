#include "VMUtils.h"
#include <windows.h>

//
// Static declarations
//
BQueue* VMUtils::HeartInQ = 0;
BQueue* VMUtils::HeartOutQ = 0;
unsigned int VMUtils::UniqueId = 0;
unsigned char VMUtils::FileSysName[8] = { 0 };
unsigned int VMUtils::HeartBeat = 0;
std::future<void> VMUtils::HeartInHandle;

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GenerateUniqueIdentifier
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::GenerateUniqueIdentifier()
{
  std::string current_dir(MAX_PATH, 0);
  GetCurrentDirectoryA(MAX_PATH, &current_dir[0]);
  current_dir = current_dir.substr(0, current_dir.find_first_of("/\\") + 1);

  unsigned int maxCompLen = 0;
  unsigned int fileSysFlags = 0;
  std::string volume_name(MAX_PATH, 0);
  std::string fileSysName(MAX_PATH, 0);
  GetVolumeInformationA(&current_dir[0], &volume_name[0], MAX_PATH,
                        reinterpret_cast<DWORD*>(&UniqueId),
                        reinterpret_cast<DWORD*>(&maxCompLen),
                        reinterpret_cast<DWORD*>(&fileSysFlags),
                        &fileSysName[0], MAX_PATH);

  // Fill in FileSysName
  memcpy(FileSysName, &fileSysName[0], FILE_SYS_LEN);

  // Generate UniqueId
  for (unsigned int i = 0; i < FILE_SYS_LEN; ++i)
  {
    UniqueId ^= static_cast<unsigned char>(FileSysName[i] << (4 * i));
  }

  // Cipher FileSysName
  for (unsigned int i = 0; i < FILE_SYS_LEN; ++i)
  {
    FileSysName[i % FILE_SYS_LEN] ^= static_cast<unsigned char>
                                     (UniqueId >> (4 * (i % sizeof(unsigned int))));
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  SetUniqueIdentifier
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::SetUniqueIdentifier(unsigned int uid, unsigned char* ruid)
{
  UniqueId = uid;
  memcpy(FileSysName, ruid, FILE_SYS_LEN);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetUniqueId
// 
/////////////////////////////////////////////////////////////////////////////////////////
unsigned int VMUtils::GetUniqueId()
{
  return UniqueId;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetFileSysName
// 
/////////////////////////////////////////////////////////////////////////////////////////
unsigned char* VMUtils::GetFileSysName()
{
  return FileSysName;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  UidString
// 
/////////////////////////////////////////////////////////////////////////////////////////
std::string VMUtils::UidString()
{
  char temp[10] = { 0 };
  sprintf_s(temp, "%08X", UniqueId);
  return std::string(&temp[0], &temp[8]);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  FileSysString
// 
/////////////////////////////////////////////////////////////////////////////////////////
std::string VMUtils::FileSysString()
{
  char temp[(FILE_SYS_LEN * 2) + 1] = { 0 };
  for (unsigned int i = 0; i < FILE_SYS_LEN; ++i)
  {
    sprintf_s(temp, "%s%02X", temp, FileSysName[i]);
  }

  return std::string(&temp[0], &temp[FILE_SYS_LEN * 2]);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetSectionName
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::GetSectionName(void* section, char* buf, unsigned int len)
{
  IMAGE_SECTION_HEADER* iSection = reinterpret_cast<IMAGE_SECTION_HEADER*>(section);
  if (0 != section)
  {
    memcpy(buf, iSection->Name, len);
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  BuildVMBuffer
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::BuildVMBuffer(unsigned int uid,
  unsigned char* ruid,
  std::vector<unsigned int> offsets,
  std::vector<unsigned int> lengths,
  std::vector<unsigned char>& buffer)
{
  // Resize buffer to accommodate data
  unsigned int numFunctions = offsets.size();
  buffer.resize(sizeof(VMHeader) + (sizeof(VMFunction) * numFunctions));

  // Point our structure to the buffer and fill in header data
  VMLayout* vml = reinterpret_cast<VMLayout*>(&buffer[0]);
  vml->header.uid = uid;
  memcpy(vml->header.ruid, ruid, FILE_SYS_LEN);
  vml->header.numFunctions = numFunctions;

  // Populate function data
  for (unsigned int i = 0; i < numFunctions; ++i)
  {
    vml->functions[i].offset = offsets[i];
    vml->functions[i].size = lengths[i];
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  XORvSection
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::XORvSection(void* section, unsigned int size)
{
  unsigned char* ptr = reinterpret_cast<unsigned char*>(section);
  for (unsigned int i = 0; i < size; ++i)
  {
    unsigned char key = 0;
    switch (i % 8)
    {
    case 0:
      key = UniqueId & 0x000000FF;
      break;
    case 1:
      key = (UniqueId & 0x00000FF0) >> 4;
      break;
    case 2:
      key = (UniqueId & 0x0000FF00) >> 8;
      break;
    case 3:
      key = (UniqueId & 0x000FF000) >> 12;
      break;
    case 4:
      key = (UniqueId & 0x00FF0000) >> 16;
      break;
    case 5:
      key = (UniqueId & 0x0FF00000) >> 20;
      break;
    case 6:
      key = (UniqueId & 0xFF000000) >> 24;
      break;
    case 7:
      key = (UniqueId & 0xF0000000) >> 28;
      break;
    }

    ptr[i] ^= key;
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  VirtualizeFunction
// 
/////////////////////////////////////////////////////////////////////////////////////////
unsigned int VMUtils::VirtualizeFunction(void* func)
{
  bool exit = false;
  unsigned int size = 0;

  unsigned long oldProtect;
  VirtualProtect(func, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

  unsigned char* ptr = reinterpret_cast<unsigned char*>(func);
  while (false == exit)
  {
    unsigned char byte = ptr[size];
    if ((byte == 0xC3) || (byte == 0xCC)) // ret or int3
    {
      break;
    }

    if ((0 != size) && (byte == 0xE9)) // Accomodate jump table.
    {
      break;
    }

    unsigned char key = 0;
    switch (size % 8)
    {
    case 0:
      key = UniqueId & 0x000000FF;
      break;
    case 1:
      key = (UniqueId & 0x00000FF0) >> 4;
      break;
    case 2:
      key = (UniqueId & 0x0000FF00) >> 8;
      break;
    case 3:
      key = (UniqueId & 0x000FF000) >> 12;
      break;
    case 4:
      key = (UniqueId & 0x00FF0000) >> 16;
      break;
    case 5:
      key = (UniqueId & 0x0FF00000) >> 20;
      break;
    case 6:
      key = (UniqueId & 0xFF000000) >> 24;
      break;
    case 7:
      key = (UniqueId & 0xF0000000) >> 28;
      break;
    }

    ptr[size] ^= key;
    ++size;
  }

  return size;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  RemoveVirtualization
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::RemoveVirtualization(void* func, unsigned int size)
{
  unsigned char* ptr = reinterpret_cast<unsigned char*>(func);

  unsigned long oldProtect;
  VirtualProtect(func, size, PAGE_EXECUTE_READWRITE, &oldProtect);

  for (unsigned int i = 0; i < size; ++i)
  {
    unsigned char key = 0;
    switch (i % 8)
    {
    case 0:
      key = UniqueId & 0x000000FF;
      break;
    case 1:
      key = (UniqueId & 0x00000FF0) >> 4;
      break;
    case 2:
      key = (UniqueId & 0x0000FF00) >> 8;
      break;
    case 3:
      key = (UniqueId & 0x000FF000) >> 12;
      break;
    case 4:
      key = (UniqueId & 0x00FF0000) >> 16;
      break;
    case 5:
      key = (UniqueId & 0x0FF00000) >> 20;
      break;
    case 6:
      key = (UniqueId & 0xFF000000) >> 24;
      break;
    case 7:
      key = (UniqueId & 0xF0000000) >> 28;
      break;
    }

    ptr[i] ^= key;
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetFuncRVAToImage
// 
/////////////////////////////////////////////////////////////////////////////////////////
void* VMUtils::GetFuncRVAToImage(void* function)
{
  unsigned long address = 0;

  // Static function RVA is based on address - Virtual Address - PointerToRawData
  PortableExecutable pe;
  if (true == pe.Attach())
  {
    address = reinterpret_cast<unsigned int>(function) -
      reinterpret_cast<unsigned int>(pe.GetBaseAddress()) -
      (pe.FirstSectionHeader->VirtualAddress -
        pe.FirstSectionHeader->PointerToRawData);
  }

  return reinterpret_cast<void*>(address);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetFuncImageToRVA
// 
/////////////////////////////////////////////////////////////////////////////////////////
void* VMUtils::GetFuncImageToRVA(unsigned int offset)
{
  unsigned long address = 0;

  // Static function RVA is based on address - Virtual Address - PointerToRawData
  PortableExecutable pe;
  if (true == pe.Attach())
  {
    address = offset + reinterpret_cast<unsigned int>(pe.GetBaseAddress()) +
      (pe.FirstSectionHeader->VirtualAddress -
        pe.FirstSectionHeader->PointerToRawData);
  }

  return reinterpret_cast<void*>(address);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetFuncOffsetRVA
// 
/////////////////////////////////////////////////////////////////////////////////////////
void* VMUtils::GetFuncOffsetRVA(unsigned int offset)
{
  unsigned long address = 0;

  // Static function RVA is based on address - Virtual Address - PointerToRawData
  PortableExecutable pe;
  if (true == pe.Attach())
  {
    address = offset - 
             (pe.FirstSectionHeader->VirtualAddress -
              pe.FirstSectionHeader->PointerToRawData);
  }

  return reinterpret_cast<void*>(address);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetRVAFuncOffset
// 
/////////////////////////////////////////////////////////////////////////////////////////
void* VMUtils::GetRVAFuncOffset(unsigned int offset)
{
  unsigned long address = 0;

  // Static function RVA is based on address - Virtual Address - PointerToRawData
  PortableExecutable pe;
  if (true == pe.Attach())
  {
    address = offset +
      (pe.FirstSectionHeader->VirtualAddress -
        pe.FirstSectionHeader->PointerToRawData);
  }

  return reinterpret_cast<void*>(address);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  ValidateUniqueId
// 
/////////////////////////////////////////////////////////////////////////////////////////
bool VMUtils::ValidateUniqueId(void* section)
{
  VMHeader* header = reinterpret_cast<VMHeader*>(section);
  if ((UniqueId == header->uid) &&
    (0 == memcmp(FileSysName, header->ruid, FILE_SYS_LEN)))
  {
    return true;
  }

  return false;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  InitializeQueues
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::InitializeQueues()
{
  GenerateUniqueIdentifier();
  HeartInQ = new BQueue(UniqueId);
  HeartOutQ = new BQueue(UniqueId + 1);

  // Launch the HeartBeat thread
  HeartInHandle = std::async(std::launch::async, &VMUtils::HeartBeatThread);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
//  Assembly functions
// 
/////////////////////////////////////////////////////////////////////////////////////////
void __declspec(naked) TerminateFunc()
{
  __asm
  {
    mov edi, edi 
    push ebp 
    xor eax, eax
    push ecx
    mov ecx, eax
    mov eax, dword ptr[0x7FF893C1]
    shl eax, 3
    pop ecx
    xor eax, ecx
    xor eax, eax
    test eax, ecx
    ret
  }
}

void __declspec(naked) TerminateFunc2()
{
  __asm
  {
    mov edi, edi
    push ebp
    xor eax, eax
    push ecx
    mov ecx, eax
    push ebx
    push [esp + 4]
    mov eax, dword ptr[0x7FF893C1]
    pop ecx
    xor eax, ecx
    xor eax, eax
    cmp eax, ecx
    ret
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  HeartBeatThread
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::HeartBeatThread()
{
  void* obj = 0;

  while (true)
  {
    // Assembly code with junk, but also checks for preset debugger..
    __asm
    {
      junk:
      pushad
      mov eax, dword ptr[UniqueId]
      shl eax, 3
      mov edx, eax
      xor eax, edx
      xor edx, eax
      shr eax, 17
      popad

      dbg_check:
      mov ecx, IsDebuggerPresent
      call ecx
      test eax, eax
      jnz bad_call
      jmp __exit

      bad_call:
      mov eax, dword ptr[UniqueId]
      call eax

      __exit :
      push eax
      push ebx
      mov eax, dword ptr[UniqueId]
      shl eax, 3
      mov ebx, eax
      xor eax, ebx
      xor ebx, eax
      shr eax, 17
      pop ebx
      pop eax
    }

    obj = HeartInQ->Pop(3000);
    if (0 == obj) // We didn't recieve a response...
    {
      TerminateFunc();
    }
    
    // Verify we have a matching counter
    if (HeartBeat != (*reinterpret_cast<unsigned int*>(obj) ^ UniqueId))
    {
      TerminateFunc();
    }

    // Free the object, send a query
    free(obj);
    obj = malloc(sizeof(unsigned int));

    ++HeartBeat;
    *reinterpret_cast<unsigned int*>(obj) = HeartBeat;
    HeartOutQ->Push(obj);

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  HeartBeatSlave
// 
/////////////////////////////////////////////////////////////////////////////////////////
void VMUtils::HeartBeatSlave()
{
  void* obj = 0;

  // Start off the heart beat master by sending in the first beat
  static bool firstCall = false;
  if (false == firstCall)
  {
    firstCall = true;
    obj = malloc(sizeof(unsigned int));
    *reinterpret_cast<unsigned int*>(obj) = HeartBeat ^ UniqueId;
    HeartInQ->Push(obj);
  }

  // Otherwise we wait for a query and respond accordingly
  obj = HeartOutQ->Pop(3000);
  if (0 == obj) // We didn't recieve a response...
  {
    TerminateFunc();
  }

  unsigned int beat = *reinterpret_cast<unsigned int*>(obj);
  if (HeartBeat != beat)
  {
    TerminateFunc();
  }

  free(obj);
  obj = malloc(sizeof(unsigned int));
  *reinterpret_cast<unsigned int*>(obj) = (HeartBeat ^ UniqueId);
  HeartInQ->Push(obj);
}