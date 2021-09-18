#pragma once

// Internal dependencies

// External dependencies
#include <mutex>
#include <queue>

// Class Definition
class BQueue
{
public:
  BQueue(unsigned int id);
  void Push(void* object);
  void* Pop(int timeout = -1);
  unsigned int Count() const;
  unsigned int GetIdentifier() const;

#ifdef _DEBUG
  void Print();
#endif

private:
  unsigned int Identifier;
  std::queue<void*> Queue;
  std::mutex QLock;
};

