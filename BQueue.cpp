#include "BQueue.h"

/****************************************************************************************
/
/
****************************************************************************************/
BQueue::BQueue(unsigned int id) :
  Identifier(id)
{
}

/****************************************************************************************
/
/
****************************************************************************************/
void BQueue::Push(void* object)
{
  while (false == QLock.try_lock())
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  Queue.push(object);
  QLock.unlock();
}

/****************************************************************************************
/
/
****************************************************************************************/
void* BQueue::Pop(int timeout)
{
  void* obj = 0;
  int currentTime = timeout;

  while (0 == this->Count())
  {
    if (0 == currentTime)     // Reached timeout
    {
      return obj;
    }
    else if (0 < currentTime) // Decrement timeout
    {
      --currentTime;
    }
  }

  while (false == QLock.try_lock())
  {
    std::this_thread::sleep_for(std::chrono::nanoseconds(1));
  }

  obj = Queue.front(); 
  Queue.pop();
  QLock.unlock();

  return obj;
}

/****************************************************************************************
/
/
****************************************************************************************/
unsigned int BQueue::Count() const
{
  return Queue.size();
}

/****************************************************************************************
/
/
****************************************************************************************/
unsigned int BQueue::GetIdentifier() const
{
  return Identifier;
}

#ifdef _DEBUG
/****************************************************************************************
/
/
****************************************************************************************/
void BQueue::Print()
{
  unsigned int count = this->Count();
  
  std::vector<void*> objects(count);
  for (unsigned int counter = count; counter > 0; --counter)
  {
    objects[counter - 1] = this->Pop();
    printf("\tObject[%d]: %08X = %08X\n",
           counter - 1,
           reinterpret_cast<unsigned int>(objects[counter - 1]),
           *reinterpret_cast<unsigned int*>(objects[counter - 1]));
  }

  for (unsigned int counter = count; counter > 0; --counter)
  {
    this->Push(objects[counter - 1]);
  }
}
#endif