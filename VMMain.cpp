#include "CRC32.h"
#include "VMUtils.h"

/////////////////////////////////////////////////////////////////////////////////////////
//
// VM Functions - Consider adding this to another file!
//
VMLayout* VLock = 0;
const char* VSectionName = ".vml";

#ifndef _DEBUG
void InitializeVM()
{
  PortableExecutable pe;
  if (true == pe.Attach())
  {
    VCPU_START();
    VMUtils::GenerateUniqueIdentifier();
    VCPU_VALIDATE();

    // Verify our section exists.
    std::string section_name(strlen(VSectionName), 0);
    VMUtils::GetSectionName(pe.LastSectionHeader, 
                            &section_name[0], 
                            section_name.size());
    if (0 != section_name.compare(VSectionName))
    {
      VTERMINATE();
    }

    // Add check for last section here
    VMUtils::XORvSection(pe.PointerToLastSection(0),
                         pe.LastSectionHeader->SizeOfRawData);

    // Exit if this is an unauthorized use.
    if (false == VMUtils::ValidateUniqueId(pe.PointerToLastSection(0)))
    {
      VTERMINATE();
    }

    // Allocate memory for VirtualLock and copy the section data over
    VLock = reinterpret_cast<VMLayout*>(malloc(sizeof(VMHeader)));
    memcpy(VLock, pe.PointerToLastSection(0), sizeof(VMHeader));

    // We now have the virtual layout, reallocate memory and copy
    unsigned int vmSize = sizeof(VMHeader) +
      (VLock->header.numFunctions * sizeof(VMFunction));
    free(VLock); // Free old mem

    VLock = reinterpret_cast<VMLayout*>(malloc(vmSize));
    memcpy(VLock, pe.PointerToLastSection(0), vmSize);
  }

  VCPU_START();
  VMUtils::InitializeQueues();
  VCPU_VALIDATE();
}

VML_EXPORT void ValidateUID()
{
  VCPU_START();
  if (false == VMUtils::ValidateUniqueId(VLock))
  {
    VTERMINATE();
  }
  VCPU_VALIDATE();
}

static unsigned int VMLCRC_VAL = 0;
void ValidateUIDCallback()
{
  VUNLOCK(ValidateUID);
  ValidateUID();
  VLOCK(ValidateUID);
}

VML_EXPORT void VMLCRC32()
{
  unsigned int vCallbackCRC = 0;
  VCPU_START();
  CRC32::CalculateCRC32(reinterpret_cast<unsigned char*>(&ValidateUIDCallback), 
                        8, // Limit CRC check 
                        vCallbackCRC);
  if (0 == VMLCRC_VAL)
  {
    VMLCRC_VAL = vCallbackCRC;
    return;
  }

  if (vCallbackCRC != VMLCRC_VAL)
  {
    VTERMINATE();
  }
  VCPU_VALIDATE();
}

void VMLCRC32Callback()
{
  VCPU_START();
  VUNLOCK(VMLCRC32);
  VMLCRC32();
  VLOCK(VMLCRC32);
  VCPU_VALIDATE();
}

void VMLHBCallback()
{
  VMUtils::HeartBeatSlave();
}

#else
void InitializeVM()
{
}

void ValidateUIDCallback()
{
}

void VMLCRC32Callback()
{
}

void VMLHBCallback()
{

}
#endif