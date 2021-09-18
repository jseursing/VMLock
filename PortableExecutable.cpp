#include "PortableExecutable.h"
#include <fstream>

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  BackupFile
// 
/////////////////////////////////////////////////////////////////////////////////////////
void PortableExecutable::BackupFile(std::string path, std::string newPath)
{
  std::ifstream src(path.c_str(), std::ios::binary);
  if (true == src.is_open())
  {
    std::ofstream dest(newPath.c_str(), std::ios::binary);
    dest << src.rdbuf();
    dest.close();
    src.close();
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  Attach
// 
/////////////////////////////////////////////////////////////////////////////////////////
bool PortableExecutable::Attach(const char* path, unsigned int preSize)
{
  // If path is not specified (NULL), this means we are attaching to the
  // current process. Otherwise we need to open the file specified by path
  // and read the file contents into memory.
  if (0 == path)
  {
    // Retrieve the virtual base address, DOS, and NT Headers.
    ImageBase = reinterpret_cast<unsigned char*>(GetModuleHandle(0));
    DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
    NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>
                (ImageBase + DosHeader->e_lfanew);
  }
  else
  {
    // Open the specified file, if the FileHandle is invalid, this means the
    // file either doesn't exist or is in use (or prohibited).
    FileHandle = CreateFileA(path,
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             0,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL,
                             0);
    if (INVALID_HANDLE_VALUE != FileHandle)
    {
      // Retrieve the total stub size, this shouldn't require too much memory
      // due to be a contentless installer. Copy the file contents to the buf.
      StubFileSize = GetFileSize(FileHandle, 0);
      FileBuffer = new unsigned char[StubFileSize + preSize];
      memset(FileBuffer, 0, StubFileSize + preSize);

      unsigned long bytesRead = 0;
      if (TRUE == ReadFile(FileHandle, FileBuffer, StubFileSize, &bytesRead, 0))
      {
        DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(FileBuffer);
        NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS32*>
                    (FileBuffer + DosHeader->e_lfanew);
      }
    }
  }

  // At this point, DosHeader and therefore NtHeaders should be NON-NULL
  // for a successful attach.
  if (0 != NtHeaders)
  {
    // Verify we are dealing with a valid portable executable.
    if ((IMAGE_DOS_SIGNATURE == DosHeader->e_magic) ||
        (IMAGE_NT_SIGNATURE == NtHeaders->Signature))
    {
      // Point FirstSectionHeader to the first section.
      FirstSectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

      // Point NewSectionHeader to the next section.
      LastSectionHeader = IMAGE_FIRST_SECTION(NtHeaders) +
                          (NtHeaders->FileHeader.NumberOfSections - 1);

      // Point ExportDirectory to specified section.
      unsigned int expVAddr = NtHeaders->OptionalHeader.DataDirectory
                              [IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

      // Update the address if dealing with a file opposed to running executable.
      SetExportRVA(expVAddr);

      // Retrieve pointer to Export Directory.
      ExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>
                        (reinterpret_cast<unsigned char*>(DosHeader) + expVAddr);

      return true;
    }
  }

  return false;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  InitializeNewSection
// 
/////////////////////////////////////////////////////////////////////////////////////////
void PortableExecutable::InitializeNewSection(const char* name)
{
  if (0 != NtHeaders)
  {
    // Point NewSectionHeader to the next section.
    NewSectionHeader = IMAGE_FIRST_SECTION(NtHeaders) +
      (NtHeaders->FileHeader.NumberOfSections);
    memset(NewSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));

    // Adjust characteristics, name the section[8], and set PointerToRawData.
    NewSectionHeader->Characteristics = IMAGE_SCN_MEM_WRITE |
                                        IMAGE_SCN_CNT_CODE |
                                        IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                                        IMAGE_SCN_MEM_EXECUTE |
                                        IMAGE_SCN_CNT_INITIALIZED_DATA |
                                        IMAGE_SCN_MEM_READ;
    memcpy(NewSectionHeader->Name, name, strlen(name));
    NewSectionHeader->PointerToRawData =
      AlignToBoundary(LastSectionHeader->PointerToRawData +
        LastSectionHeader->SizeOfRawData,
        NtHeaders->OptionalHeader.FileAlignment);
    NewSectionHeader->VirtualAddress =
      AlignToBoundary(LastSectionHeader->VirtualAddress +
        LastSectionHeader->Misc.VirtualSize,
        NtHeaders->OptionalHeader.SectionAlignment);

    // For our use case, we do not know the current size of this new section (yet)
    // and will wait for FinalizeNewSection() to fill this out.
    
    // Update LastSectionHeader
    LastSectionHeader = NewSectionHeader;
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  FinalizeNewSection
// 
/////////////////////////////////////////////////////////////////////////////////////////
void PortableExecutable::FinalizeNewSection(unsigned int totalSize)
{
  if (0 != NewSectionHeader)
  {
    // Set the corresponding size and locations of the section in relation
    // to the section/file byte alignment.
    NewSectionHeader->Misc.VirtualSize =
      AlignToBoundary(totalSize, NtHeaders->OptionalHeader.SectionAlignment);
    NewSectionHeader->SizeOfRawData =
      AlignToBoundary(totalSize, NtHeaders->OptionalHeader.FileAlignment);

    // Update the current image size.
    NtHeaders->OptionalHeader.SizeOfImage =
      AlignToBoundary(NewSectionHeader->VirtualAddress +
        NewSectionHeader->Misc.VirtualSize,
        NtHeaders->OptionalHeader.SectionAlignment);

    // Increaes the section count.
    ++NtHeaders->FileHeader.NumberOfSections;

    // Write the PE Header contents to the file and update the
    // end of file location.
    unsigned long written = 0;
    unsigned int totalSize = NewSectionHeader->PointerToRawData + 
                             NewSectionHeader->SizeOfRawData;
    SetFilePointer(FileHandle, 0, 0, FILE_BEGIN);
    WriteFile(FileHandle, FileBuffer, totalSize, &written, 0);
    SetFilePointer(FileHandle, totalSize, 0, FILE_BEGIN);
    SetEndOfFile(FileHandle);

    // Free the FileBuffer memory now that it is no longer of us.
    delete[] FileBuffer;
    FileBuffer = 0;
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  InsertIntoNewSection
// 
/////////////////////////////////////////////////////////////////////////////////////////
void PortableExecutable::InsertIntoNewSection(unsigned char* data,
                                              unsigned int len,
                                              unsigned int offset) const
{
  if (INVALID_HANDLE_VALUE != FileHandle)
  {
    SetFilePointer(FileHandle,
                   NewSectionHeader->PointerToRawData + offset,
                   0,
                   FILE_BEGIN);

    unsigned long bytesWritten = 0;
    WriteFile(FileHandle, data, len, &bytesWritten, 0);

    // Update file buffer
    memcpy(&FileBuffer[NewSectionHeader->PointerToRawData + offset], data, len);
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  ExtractFromLastSection
// 
/////////////////////////////////////////////////////////////////////////////////////////
void PortableExecutable::ExtractFromLastSection(unsigned char* buf,
                                                unsigned int offset,
                                                unsigned int len) const
{
  if (LastSectionHeader->SizeOfRawData > offset)
  {
    void* source = reinterpret_cast<void*>
                   (ImageBase + LastSectionHeader->VirtualAddress + offset);
    memcpy(buf, source, len);
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  PointerToLastSection
// 
/////////////////////////////////////////////////////////////////////////////////////////
char* PortableExecutable::PointerToLastSection(unsigned int offset)
{
  return reinterpret_cast<char*>(ImageBase + LastSectionHeader->VirtualAddress + offset);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  PointerToLastSection
// 
/////////////////////////////////////////////////////////////////////////////////////////
unsigned char* PortableExecutable::PtrToLastSectionBuf(unsigned int offset)
{
  return &FileBuffer[LastSectionHeader->PointerToRawData + offset];
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  DestroyExportFunction
// 
/////////////////////////////////////////////////////////////////////////////////////////
bool PortableExecutable::DestroyExportFunction(unsigned int offset, 
                                               unsigned int numDeleted)
{
  for (unsigned int i = 0; i < ExportDirectory->NumberOfFunctions + numDeleted; ++i)
  {
    unsigned int addressOfNames = ExportDirectory->AddressOfNames;
    SetExportRVA(addressOfNames);

    unsigned int funcNameAddress = reinterpret_cast<unsigned int*>
      (reinterpret_cast<char*>(DosHeader) + addressOfNames)[i];
    SetExportRVA(funcNameAddress);

    unsigned int addressOfOrdinals = ExportDirectory->AddressOfNameOrdinals;
    SetExportRVA(addressOfOrdinals);

    unsigned int addressOfFunctions = ExportDirectory->AddressOfFunctions;
    SetExportRVA(addressOfFunctions);

    char* functionName = reinterpret_cast<char*>
      (reinterpret_cast<char*>(DosHeader) + funcNameAddress);
    unsigned short functionOrd = reinterpret_cast<unsigned short*>
      (reinterpret_cast<char*>(DosHeader) + addressOfOrdinals)[i];
    unsigned int functionOffset = reinterpret_cast<unsigned int*>
      (reinterpret_cast<char*>(DosHeader) + addressOfFunctions)[i];

    if (functionOffset == offset)
    {
      // Clear function name
      memset(functionName, 0, strlen(functionName));

      // Clear function ordinal
      reinterpret_cast<unsigned short*>
        (reinterpret_cast<char*>(DosHeader) + addressOfOrdinals)[i] = 0;

      // Clear function address
      reinterpret_cast<unsigned int*>
        (reinterpret_cast<char*>(DosHeader) + addressOfFunctions)[i] = 0;

      // Decrement Number of functions
      --ExportDirectory->NumberOfFunctions;

      return true;
    }
  }

  return false;
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  SetExportRVA
// 
/////////////////////////////////////////////////////////////////////////////////////////
void PortableExecutable::SetExportRVA(unsigned int& virtual_addr)
{
  // If we are dealing with a file opposed to a running executable,
  // the data directory resides somewhere inside one of the sections.
  if (0 != FileBuffer)
  {
    for (IMAGE_SECTION_HEADER* section = FirstSectionHeader;
         section != LastSectionHeader;
         ++section)
    {
      if (virtual_addr < (section->VirtualAddress + section->Misc.VirtualSize))
      {
        virtual_addr = section->PointerToRawData + 
                       virtual_addr - 
                       section->VirtualAddress;
        break;
      }
    }
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  GetBaseAddress
// 
/////////////////////////////////////////////////////////////////////////////////////////
void* PortableExecutable::GetBaseAddress()
{
  return reinterpret_cast<void*>(DosHeader);
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  Constructor
// 
/////////////////////////////////////////////////////////////////////////////////////////
PortableExecutable::PortableExecutable() :
  FileHandle(INVALID_HANDLE_VALUE),
  ImageBase(0),
  FileBuffer(0),
  StubFileSize(0),
  DosHeader(0),
  NtHeaders(0),
  FirstSectionHeader(0),
  LastSectionHeader(0),
  NewSectionHeader(0),
  ExportDirectory(0)
{

}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  Destructor
// 
/////////////////////////////////////////////////////////////////////////////////////////
PortableExecutable::~PortableExecutable()
{
  if (INVALID_HANDLE_VALUE != FileHandle)
  {
    CloseHandle(FileHandle);
  }

  // Incase ::FinalizeNewSection() was not called, free the memory.
  if (0 != FileBuffer)
  {
    delete[] FileBuffer;
    FileBuffer = 0;
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Function:  AlignToBoundary
// 
/////////////////////////////////////////////////////////////////////////////////////////
unsigned int PortableExecutable::AlignToBoundary(unsigned int address,
                                                 unsigned int alignment)
{
  unsigned int correction = address % alignment;

  return address + (0 == correction ? 0 : alignment - correction);
}
