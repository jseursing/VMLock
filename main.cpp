#include "VMLock.h"
#include <QtWidgets/QApplication>

#ifdef STUB_APP
#include "PortableExecutable.h"
#include "VMUtils.h"
#include <stdio.h>
void funcTest1()
{
  printf("funcTest1\n");
}
void funcTest2()
{
  printf("funcTest2\n");
}
void funcTest3()
{
  printf("funcTest3\n");
}
#endif

int main(int argc, char *argv[])
{
#ifndef STUB_APP
  QApplication a(argc, argv);
  VMLock w;
  w.show();
  return a.exec();
#else
  AllocConsole();
  freopen("CONOUT$", "w", stdout);
  LOC_FUNC(funcTest1);
  LOC_FUNC(funcTest2);
  LOC_FUNC(funcTest3);

  // Use VMUtils to devirtualize our last section
  PortableExecutable pe;
  if (true == pe.Attach())
  {
    // Generate UID
    VMUtils::GenerateUniqueIdentifier();

    // Remove last section virtualization
    VMUtils::XORvSection(pe.PointerToLastSection(0), 
                         pe.LastSectionHeader->SizeOfRawData);

    // Validate UID
    if (false == VMUtils::ValidateUniqueId(pe.PointerToLastSection(0)))
    {
      printf("You are not authorized to use this.");
      TerminateProcess(GetCurrentProcess(), 0);
    }

      VUNLOCK(funcTest1);
      funcTest1();
      VUNLOCK(funcTest2);
      funcTest2();
      VUNLOCK(funcTest3);
      funcTest3();
      VLOCK(funcTest1);
      VLOCK(funcTest2);
      VLOCK(funcTest3);
      VUNLOCK(funcTest1);
      VUNLOCK(funcTest2);
      VUNLOCK(funcTest3);
      funcTest1();
      funcTest2();
      funcTest3();
    }
  }

  while (true) {}
#endif
}
