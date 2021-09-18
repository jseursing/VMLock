#pragma once
#include <string>
#include <Windows.h>

struct FunctionExport
{
  std::string name;
  unsigned int address;
};

class PortableExecutable
{
public:
  static void BackupFile(std::string path, std::string newPath);

  bool Attach(const char* path = 0, unsigned int preSize = 0);
  void InitializeNewSection(const char* name);
  void FinalizeNewSection(unsigned int totalSize);
  void InsertIntoNewSection(unsigned char* data,
                            unsigned int len,
                            unsigned int offset) const;
  void ExtractFromLastSection(unsigned char* buf,
                              unsigned int offset,
                              unsigned int len) const;
  char* PointerToLastSection(unsigned int offset);
  unsigned char* PtrToLastSectionBuf(unsigned int offset);
  bool DestroyExportFunction(unsigned int offset, unsigned int numDeleted);
  void SetExportRVA(unsigned int& virtual_addr);
  void* GetBaseAddress();
  PortableExecutable();
  ~PortableExecutable();

  // Public members to be accessed outside of class
  IMAGE_DOS_HEADER* DosHeader;
  IMAGE_NT_HEADERS* NtHeaders;
  IMAGE_SECTION_HEADER* FirstSectionHeader;
  IMAGE_SECTION_HEADER* LastSectionHeader;
  IMAGE_SECTION_HEADER* NewSectionHeader;
  IMAGE_EXPORT_DIRECTORY* ExportDirectory;

private:
  unsigned int AlignToBoundary(unsigned int address, unsigned int alignment);

  HANDLE FileHandle;
  unsigned char* ImageBase;
  unsigned char* FileBuffer;
  unsigned int StubFileSize;
};

