#pragma once
#define FILE_SYS_LEN 8

struct VMHeader
{
  unsigned int uid;
  unsigned char ruid[FILE_SYS_LEN];
  unsigned int numFunctions;
};

struct VMFunction
{
  unsigned int offset;
  unsigned int size;
};

struct VMLayout
{
  VMHeader header;
  VMFunction functions[0];
};