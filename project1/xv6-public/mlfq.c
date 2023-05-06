#include "types.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"

void yield(void);
int getLevel(void);
void setPriority(int pid, int priority);
void schedulerLock(int password);
void schedulerUnlock(int password);

void
yield(void)
{
  acquire(&ptable.lock);
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}