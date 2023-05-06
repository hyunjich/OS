#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct
{
    struct spinlock lock;
    struct proc proc[NPROC];
    struct
    {
        struct proc *addr[3][NPROC]; // where processor is
        int num[3];                  // number of process in each level
        struct proc *lock_proc;      // lock된 프로세스
    } Mlfq;
} ptable;

static struct proc *initproc;
int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void pinit(void)
{
    // mlfq 각 레벨에 있는 프로세서 초기화
    acquire(&ptable.lock);
    ptable.Mlfq.lock_proc = 0;
    ptable.Mlfq.num[0] = 0;
    ptable.Mlfq.num[1] = 0;
    ptable.Mlfq.num[2] = 0;
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < NPROC; j++)
        {
            ptable.Mlfq.addr[i][j] = 0;
        }
    }
    release(&ptable.lock);
    initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int cpuid()
{
    return mycpu() - cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu *
mycpu(void)
{
    int apicid, i;

    if (readeflags() & FL_IF)
        panic("mycpu called with interrupts enabled\n");

    apicid = lapicid();
    // APIC IDs are not guaranteed to be contiguous. Maybe we should have
    // a reverse map, or reserve a register to store &cpus[i].
    for (i = 0; i < ncpu; ++i)
    {
        if (cpus[i].apicid == apicid)
            return &cpus[i];
    }
    panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc *
myproc(void)
{
    struct cpu *c;
    struct proc *p;
    pushcli();
    c = mycpu();
    p = c->proc;
    popcli();
    return p;
}

// PAGEBREAK: 32
//  Look in the process table for an UNUSED proc.
//  If found, change state to EMBRYO and initialize
//  state required to run in the kernel.
//  Otherwise return 0.
static struct proc *
allocproc(void)
{
    struct proc *p;
    char *sp;

    acquire(&ptable.lock);

    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
        if (p->state == UNUSED)
            goto found;

    release(&ptable.lock);
    return 0;

found:
    p->state = EMBRYO;
    p->pid = nextpid++;

    // 프로세스의 정보 및 mlfq의 정보 선언
    p->time_quantum = 4;
    p->level = 0;
    p->priority = 3;
    ptable.Mlfq.addr[0][ptable.Mlfq.num[0]++] = p;
    release(&ptable.lock);

    // Allocate kernel stack.
    if ((p->kstack = kalloc()) == 0)
    {
        p->state = UNUSED;
        return 0;
    }
    sp = p->kstack + KSTACKSIZE;

    // Leave room for trap frame.
    sp -= sizeof *p->tf;
    p->tf = (struct trapframe *)sp;

    // Set up new context to start executing at forkret,
    // which returns to trapret.
    sp -= 4;
    *(uint *)sp = (uint)trapret;

    sp -= sizeof *p->context;
    p->context = (struct context *)sp;
    memset(p->context, 0, sizeof *p->context);
    p->context->eip = (uint)forkret;
    return p;
}

// PAGEBREAK: 32
//  Set up first user process.
void userinit(void)
{
    struct proc *p;
    extern char _binary_initcode_start[], _binary_initcode_size[];

    p = allocproc();

    initproc = p;
    if ((p->pgdir = setupkvm()) == 0)
        panic("userinit: out of memory?");
    inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
    p->sz = PGSIZE;
    memset(p->tf, 0, sizeof(*p->tf));
    p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
    p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
    p->tf->es = p->tf->ds;
    p->tf->ss = p->tf->ds;
    p->tf->eflags = FL_IF;
    p->tf->esp = PGSIZE;
    p->tf->eip = 0; // beginning of initcode.S

    safestrcpy(p->name, "initcode", sizeof(p->name));
    p->cwd = namei("/");

    // this assignment to p->state lets other cores
    // run this process. the acquire forces the above
    // writes to be visible, and the lock is also needed
    // because the assignment might not be atomic.
    acquire(&ptable.lock);

    p->state = RUNNABLE;

    release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
    uint sz;
    struct proc *curproc = myproc();

    sz = curproc->sz;
    if (n > 0)
    {
        if ((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
            return -1;
    }
    else if (n < 0)
    {
        if ((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
            return -1;
    }
    curproc->sz = sz;
    switchuvm(curproc);
    return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int fork(void)
{
    int i, pid;
    struct proc *np;
    struct proc *curproc = myproc();

    // Allocate process.
    if ((np = allocproc()) == 0)
    {
        return -1;
    }

    // Copy process state from proc.
    if ((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0)
    {
        kfree(np->kstack);
        np->kstack = 0;
        np->state = UNUSED;
        return -1;
    }
    np->sz = curproc->sz;
    np->parent = curproc;
    *np->tf = *curproc->tf;

    // Clear %eax so that fork returns 0 in the child.
    np->tf->eax = 0;

    for (i = 0; i < NOFILE; i++)
        if (curproc->ofile[i])
            np->ofile[i] = filedup(curproc->ofile[i]);
    np->cwd = idup(curproc->cwd);

    safestrcpy(np->name, curproc->name, sizeof(curproc->name));

    pid = np->pid;

    acquire(&ptable.lock);

    np->state = RUNNABLE;

    release(&ptable.lock);
    return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void exit(void)
{
    struct proc *curproc = myproc();
    struct proc *p;
    int fd;
    int k;

    if (curproc == initproc)
        panic("init exiting");

    // Close all open files.
    for (fd = 0; fd < NOFILE; fd++)
    {
        if (curproc->ofile[fd])
        {
            fileclose(curproc->ofile[fd]);
            curproc->ofile[fd] = 0;
        }
    }

    begin_op();
    iput(curproc->cwd);
    end_op();
    curproc->cwd = 0;

    acquire(&ptable.lock);

    // Parent might be sleeping in wait().
    wakeup1(curproc->parent);
    if (ptable.Mlfq.lock_proc != 0)
    {
        ptable.Mlfq.lock_proc = 0;
    }
    //해당 프로세스 테이블에서 지우기
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < ptable.Mlfq.num[i]; j++)
        {
            if (curproc->pid == ptable.Mlfq.addr[i][j]->pid)
            {
                for (k = j; k < ptable.Mlfq.num[i]; k++)
                {
                    ptable.Mlfq.addr[i][k] = ptable.Mlfq.addr[i][k + 1];
                }
                ptable.Mlfq.num[i]--;
                goto delete_done;
            }
        }
    }

delete_done:
    // Pass abandoned children to init.
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
        if (p->parent == curproc)
        {
            p->parent = initproc;
            if (p->state == ZOMBIE)
                wakeup1(initproc);
        }
    }

    // Jump into the scheduler, never to return.
    curproc->state = ZOMBIE;
    sched();
    panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int wait(void)
{
    struct proc *p;
    int havekids, pid;
    struct proc *curproc = myproc();

    acquire(&ptable.lock);
    for (;;)
    {
        // Scan through table looking for exited children.
        havekids = 0;
        for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
        {
            if (p->parent != curproc)
                continue;
            havekids = 1;
            if (p->state == ZOMBIE)
            {
                // Found one.
                pid = p->pid;
                kfree(p->kstack);
                p->kstack = 0;
                freevm(p->pgdir);
                p->pid = 0;
                p->parent = 0;
                p->name[0] = 0;
                p->killed = 0;
                p->state = UNUSED;
                release(&ptable.lock);
                return pid;
            }
        }

        // No point waiting if we don't have any children.
        if (!havekids || curproc->killed)
        {
            release(&ptable.lock);
            return -1;
        }

        // Wait for children to exit.  (See wakeup1 call in proc_exit.)
        sleep(curproc, &ptable.lock); // DOC: wait-sleep
    }
}

// this down grade the process to lower level
void mlfq_down(struct proc *p)
{
    int i;

    if (p->level == 0)
    {
        p->level = 1;
        p->time_quantum = 6;
        ptable.Mlfq.num[0]--;
        ptable.Mlfq.addr[1][ptable.Mlfq.num[1]++] = p;
        // L0에서 내려간 프로세스 기준 앞으로 밀착
        for(i = 0; i< ptable.Mlfq.num[0]; i++)
        {
            if(p->pid == ptable.Mlfq.addr[0][i]->pid)
                break;
        }
        for (int j = i; j < ptable.Mlfq.num[0] + 1; j++)
        {
            ptable.Mlfq.addr[0][j] = ptable.Mlfq.addr[0][j + 1];
        }
    }
    else if (p->level == 1)
    {
        p->level = 2;
        p->time_quantum = 8;
        ptable.Mlfq.num[1]--;
        ptable.Mlfq.addr[2][ptable.Mlfq.num[2]++] = p;
        // L1에서 내려간 프로세스 기준 앞으로 밀착
        for(i = 0; i< ptable.Mlfq.num[1]; i++)
        {
            if(p->pid == ptable.Mlfq.addr[1][i]->pid)
                break;
        }
         for (int j = i; j < ptable.Mlfq.num[1] + 1; j++)
        {
            ptable.Mlfq.addr[1][j] = ptable.Mlfq.addr[1][j + 1];
        }
    }
}

void priority_boosting()
{
    int j = 0;
    // L1의 프로세스 L0로 옮겨주기
    for (int i = ptable.Mlfq.num[0]; i < ptable.Mlfq.num[1] + ptable.Mlfq.num[0]; i++)
    {
        ptable.Mlfq.addr[0][i] = ptable.Mlfq.addr[1][j];
        ptable.Mlfq.addr[1][j++] = 0;
    }
    ptable.Mlfq.num[0] = ptable.Mlfq.num[0] + ptable.Mlfq.num[1];
    ptable.Mlfq.num[1] = 0;
    j = 0;
    // L2의 프로세스 L0로 옮겨주기
    for (int i = ptable.Mlfq.num[0]; i < ptable.Mlfq.num[2] + ptable.Mlfq.num[0]; i++)
    {
        ptable.Mlfq.addr[0][i] = ptable.Mlfq.addr[2][j];
        ptable.Mlfq.addr[2][j++] = 0;
    }
    ptable.Mlfq.num[0] = ptable.Mlfq.num[0] + ptable.Mlfq.num[2];
    ptable.Mlfq.num[2] = 0;
    // L0의 프로세스 정보 초기화
    for (int i = 2; i < ptable.Mlfq.num[0]; i++)
    {
        ptable.Mlfq.addr[0][i]->priority = 3;
        ptable.Mlfq.addr[0][i]->time_quantum = 4;
        ptable.Mlfq.addr[0][i]->level = 0;
    }
    ticks = 0;
}

// PAGEBREAK: 42
//  Per-CPU process scheduler.
//  Each CPU calls scheduler() after setting itself up.
//  Scheduler never returns.  It loops, doing:
//   - choose a process to run
//   - swtch to start running that process
//   - eventually that process transfers control
//       via swtch back to the scheduler.
void scheduler(void)
{
    // cprintf("scheduler\n");
    struct proc *p;
    struct cpu *c = mycpu();
    c->proc = 0;

    for (;;)
    {
        // Enable interrupts on this processor.
        sti();

        // Loop over process table looking for process to run.
        acquire(&ptable.lock);
        for (int i = 0; i < 3; i++)
        {
            // for문 이기때문에 l0 l1 l2 순으로 우선순위 메겨짐
            for (int j = 0; j < ptable.Mlfq.num[i]; j++)
            {
                p = ptable.Mlfq.addr[i][j];
                if (p->state != RUNNABLE)
                    continue;

                // Switch to chosen process.  It is the process's job
                // to release ptable.lock and then reacquire it
                // before jumping back to us.
                // L2에서의 우선순위 FCFS를 구현
                if (i == 2)
                {
                    for (int k = 0; k < ptable.Mlfq.num[2]; k++)
                    {
                        if (p->priority > ptable.Mlfq.addr[2][k]->priority)
                            p = ptable.Mlfq.addr[2][k];
                    }
                }
                // lock_proc에 프로세스가 있다면 그 프로세스 실행
                if (ptable.Mlfq.lock_proc != 0)
                    p = ptable.Mlfq.lock_proc;

                c->proc = p;
                switchuvm(p);
                p->state = RUNNING;

                swtch(&(c->scheduler), p->context);
                switchkvm();
                // priority boosting
                if (ticks >= 100)
                    priority_boosting();
                // tick이 해당 레벨 time_quantum 넘어가면 mlfq level내려주기
                if ((p->level == 0 || p->level == 1) && p->time_quantum == 0)
                    mlfq_down(p);
               
                
                // Process is done running for now.
                // It should have changed its p->state before coming back.
                c->proc = 0;

                
            }
        }
        release(&ptable.lock);
    }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
    int intena;
    struct proc *p = myproc();

    if (!holding(&ptable.lock))
        panic("sched ptable.lock");
    if (mycpu()->ncli != 1)
        panic("sched locks");
    if (p->state == RUNNING)
        panic("sched running");
    if (readeflags() & FL_IF)
        panic("sched interruptible");
    intena = mycpu()->intena;
    swtch(&p->context, mycpu()->scheduler);
    mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
    acquire(&ptable.lock); // DOC: yieldlock
    myproc()->state = RUNNABLE;
    sched();
    release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void forkret(void)
{
    static int first = 1;
    // Still holding ptable.lock from scheduler.
    release(&ptable.lock);

    if (first)
    {
        // Some initialization functions must be run in the context
        // of a regular process (e.g., they call sleep), and thus cannot
        // be run from main().
        first = 0;
        iinit(ROOTDEV);
        initlog(ROOTDEV);
    }

    // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
    struct proc *p = myproc();

    if (p == 0)
        panic("sleep");

    if (lk == 0)
        panic("sleep without lk");

    // Must acquire ptable.lock in order to
    // change p->state and then call sched.
    // Once we hold ptable.lock, we can be
    // guaranteed that we won't miss any wakeup
    // (wakeup runs with ptable.lock locked),
    // so it's okay to release lk.
    if (lk != &ptable.lock)
    {                          // DOC: sleeplock0
        acquire(&ptable.lock); // DOC: sleeplock1
        release(lk);
    }
    // Go to sleep.
    p->chan = chan;
    p->state = SLEEPING;

    sched();

    // Tidy up.
    p->chan = 0;

    // Reacquire original lock.
    if (lk != &ptable.lock)
    { // DOC: sleeplock2
        release(&ptable.lock);
        acquire(lk);
    }
}

// PAGEBREAK!
//  Wake up all processes sleeping on chan.
//  The ptable lock must be held.
static void
wakeup1(void *chan)
{
    struct proc *p;

    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
        if (p->state == SLEEPING && p->chan == chan)
            p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void wakeup(void *chan)
{
    acquire(&ptable.lock);
    wakeup1(chan);
    release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int kill(int pid)
{
    struct proc *p;

    acquire(&ptable.lock);
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
        if (p->pid == pid)
        {
            p->killed = 1;
            // Wake process from sleep if necessary.
            if (p->state == SLEEPING)
                p->state = RUNNABLE;
            release(&ptable.lock);
            return 0;
        }
    }
    release(&ptable.lock);
    return -1;
}

// PAGEBREAK: 36
//  Print a process listing to console.  For debugging.
//  Runs when user types ^P on console.
//  No lock to avoid wedging a stuck machine further.
void procdump(void)
{
    static char *states[] = {
        [UNUSED] "unused",
        [EMBRYO] "embryo",
        [SLEEPING] "sleep ",
        [RUNNABLE] "runble",
        [RUNNING] "run   ",
        [ZOMBIE] "zombie"};
    int i;
    struct proc *p;
    char *state;
    uint pc[10];

    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
        if (p->state == UNUSED)
            continue;
        if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
            state = states[p->state];
        else
            state = "???";
        cprintf("%d %s %s", p->pid, state, p->name);
        if (p->state == SLEEPING)
        {
            getcallerpcs((uint *)p->context->ebp + 2, pc);
            for (i = 0; i < 10 && pc[i] != 0; i++)
                cprintf(" %p", pc[i]);
        }
        cprintf("\n");
    }
}

int getLevel(void)
{
    int a = myproc()->level;
    return a;
}

void setPriority(int pid, int priority)
{
    acquire(&ptable.lock);
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < ptable.Mlfq.num[i]; j++)
        {
            //프로세스 찾아서 priority 수정
            if (ptable.Mlfq.addr[i][j]->pid == pid)
                ptable.Mlfq.addr[i][j]->priority = priority;
        }
    }
    release(&ptable.lock);
}

void schedulerLock(int password)
{
    acquire(&ptable.lock);

    if (password == 2019015496)
    {
        //ptable.Mlfq.lock_proc에 현재 프로세스 넣기
        ptable.Mlfq.lock_proc = myproc();
    }
    else
    {
        cprintf("pid: %d  time_quantum: %d  level: %d\n", myproc()->pid, myproc()->time_quantum, myproc()->level);
        exit();
    }
    release(&ptable.lock);
}

void schedulerUnlock(int password)
{
    acquire(&ptable.lock);
    if (password == 2019015496)
    {
        //모든 프로세스 앞에서부터 한 칸씩 밀어주기
        for (int i = ptable.Mlfq.num[0]; i > 0; i--)
        {
            ptable.Mlfq.addr[0][i] = ptable.Mlfq.addr[0][i - 1];
        }
        //l0가장 앞에 lock되어있던 프로세스 넣고 정보 초기화
        ptable.Mlfq.addr[0][0] = ptable.Mlfq.lock_proc;
        ptable.Mlfq.num[0]++;
        myproc()->level = 0;
        myproc()->time_quantum = 4;
        myproc()->priority = 3;
        ptable.Mlfq.lock_proc = 0;
    }
    else
    {
        cprintf("pid: %d  time_quantum: %d  level: %d\n", myproc()->pid, myproc()->time_quantum, myproc()->level);
        exit();
    }
    release(&ptable.lock);
}