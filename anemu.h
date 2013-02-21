#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <assert.h>

#if HAVE_SETRLIMIT
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif

/* rasm2 disassembler */
#include <r_types.h>
#include <r_asm.h>

/* darm disassembler */
#include <darm.h>
#define I_IVLD -1               /* TODO: move to darm */

#define SIGNAL SIGTRAP
#define SEGV_FAULT_ADDR (void *)0xdeadbeef
#define UCONTEXT_REG_OFFSET 3   /* skip first 3 fields (trap_no, error_code, oldmask) of uc_mcontext */

#define cpu(reg) (emu.current.uc_mcontext.arm_##reg)
#define REG(reg) ((unsigned long *)&emu.current.uc_mcontext)[reg + UCONTEXT_REG_OFFSET]
#define EMU(Rd, Rn, op, imm)                                      \
    printf("EMU: r%d = r%d %s %x\n", d->Rd, d->Rn, #op, d->imm);  \
    REG(d->Rd) = REG(d->Rn) op d->imm;

#define emu_reg_value(reg) cpu(reg)
#define emu_reg_set(reg, val) cpu(reg) = (val)

typedef struct _cpsr_t {
    uint8_t N;                  /* Negative result */
    uint8_t Z;                  /* Zero result */
    uint8_t C;                  /* Carry from operation */
    uint8_t V;                  /* oVerflowed operation */
} cpsr_t;

typedef struct _emu_t {
    ucontext_t original;        /* process state when trap occured */
    ucontext_t current;         /* present process emulated state */
    ucontext_t previous;        /* used for diff-ing two contexts */
    int        initialized;     /* boolean */
    /* taint_t taint; */
} emu_t;

static const char *reg_names[] = { "r0", "r1", "r2", "r3", "r4", "r5",
                                   "r6", "r7", "r8", "r9", "r10",
                                   "fp", "ip", "sp", "lr", "pc"};

#define REG_NAME(reg) (reg_names[reg])

#define SIGCONTEXT_REG_COUNT 21
static const char *sigcontext_names[] = {"trap_no", "error_code", "oldmask",
                                         "r0", "r1", "r2", "r3", "r4", "r5",
                                         "r6", "r7", "r8", "r9", "r10",
                                         "fp", "ip", "sp", "lr", "pc", "cpsr",
                                         "fault_address"};


/* Internal state */
emu_t emu;                      /* emulator state */
cpsr_t cpsr;                    /* cpsr NZCV flags */
struct r_asm_t *rasm;           /* rasm2 disassembler */
darm_t *darm;                   /* darm  disassembler */

/*
 * Signal context structure - contains all info to do with the state
 * before the signal handler was invoked.  Note: only add new entries
 * to the end of the structure.
 */
/* 
struct sigcontext {
    unsigned long trap_no;
    unsigned long error_code;
    unsigned long oldmask;
    unsigned long arm_r0;
    unsigned long arm_r1;
    unsigned long arm_r2;
    unsigned long arm_r3;
    unsigned long arm_r4;
    unsigned long arm_r5;
    unsigned long arm_r6;
    unsigned long arm_r7;
    unsigned long arm_r8;
    unsigned long arm_r9;
    unsigned long arm_r10;
    unsigned long arm_fp;
    unsigned long arm_ip;
    unsigned long arm_sp;
    unsigned long arm_lr;
    unsigned long arm_pc;
    unsigned long arm_cpsr;
    unsigned long fault_address;
};
*/

/* API */

void emu_init();
void emu_start(ucontext_t *ucontext);
void emu_stop();
int emu_stop_trigger(const char *assembly);

void emu_handler(int sig, siginfo_t *si, void *ucontext);
void emu_register_handler(void* sig_handler);

int emu_regs_clean();

const char* emu_disas(unsigned int pc);
const darm_t* emu_darm(unsigned int pc);

void emu_type_arith_shift(const darm_t * d);
void emu_type_arith_imm(const darm_t * d);
void emu_type_branch_syscall(const darm_t * d);
void emu_type_branch_misc(const darm_t * d);
void emu_type_move_imm(const darm_t * d);
void emu_type_cmp_imm(const darm_t * d);
void emu_type_cmp_op(const darm_t * d);
void emu_type_opless(const darm_t * d);
void emu_type_dst_src(const darm_t * d);

/* Debugging / Internal only */
int test_c(int arg);
extern int test_asm(int arg);
static int execute_instr();
static void dbg_dump_ucontext(ucontext_t *uc);
static void emu_dump();
static void emu_dump_diff();
/* static inline unsigned long REG(int reg); */
/* static inline unsigned long * WREG(int reg); */

#endif  /* _INCLUDE_ANEMU_H_ */
