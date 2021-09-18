#pragma once

class CRC32
{
public:
  static void CalculateCRC32(unsigned char* buf, unsigned int len, unsigned int& crc);

private:
  static const unsigned char CRCLookupTable[255];
  static const unsigned int INITIAL_REMAINDER = 0xFFFFFFFF;
  static const unsigned int FINAL_EXCLUSIVE_OR = 0xFFFFFFFF;
};

