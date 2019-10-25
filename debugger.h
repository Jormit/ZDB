#pragma once

#include "elf-parser.h"
#include <sys/user.h>
#include <capstone/capstone.h>

// Possible states debugger can be in.
#define not_running 0x1
#define at_break 0x2

// Struct for storing breakpoints in linked list.
struct breakpoint {
	long long unsigned int address;
	long old_data;
	struct breakpoint *next;
};

// Head of the breakpoint struct
struct head {
	struct breakpoint *list;
};

// Debugging functions.
void start_child(char *argv[]);
void start_debugger(pid_t pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head);

void set_rip(pid_t pid, long addr);

// Add breakpoint to list.
struct breakpoint *add_breakpoint(long long unsigned int address, struct head *bp_head);

// Find breakpoint.
struct breakpoint *find_breakpoint(long long unsigned int address, struct head *bp_head, int *num);

// Setting breakpoint in code.
long set_breakpoint(pid_t pid, long addr);
void unset_breakpoint(pid_t pid, long addr, long old_data);
void set_all_breaks(pid_t pid, struct head *bp_head);

void disas(pid_t pid, int length, long location, int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[], long rip, char *raw_file);

// Movement functions.
void run(char *argv[], pid_t *pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head);
void cont(pid_t pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head);
void cont_ss(pid_t pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head);

// Printing functions.
void print_registers(struct user_regs_struct *regs);
void print_stack(pid_t pid, long sp, long amount);
void print_all_breaks(struct head *bp_head);