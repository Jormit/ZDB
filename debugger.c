#include <stdio.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/user.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <ctype.h>

#include "colors.h"
#include "elf-parser.h"
#include "debugger.h"

void run(char *argv[], pid_t *pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head){
	int status;	
	if (*tracee_status == at_break){
		printf("[/] restarting.\n");
		kill(*pid, SIGKILL);
		wait(&status);
	}	
	
	*pid = fork();

	if (*pid == 0){
		// Child process.
		start_child(argv);
	} else {
		// Parent process.		
		start_debugger(*pid, regs, tracee_status, bp_head);
	}
}

void start_child(char *argv[]){
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	execl(argv[1], argv[1], NULL);
}

void start_debugger(pid_t pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head){
	int status;
	wait(&status); 

	// Set all stored break points.
	set_all_breaks(pid, bp_head);

	//long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)main_addr, 0);
	//printf("%lx\n", data);	

	return;
}

void disas(pid_t pid, int length, long location, int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[], long rip, char *raw_file) {	
	//#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
	
	char *code = malloc(sizeof(long) * (length));

	for (int i = 0; i < (length); i++){
		long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)location + 8 * i, 0);
		memcpy(code + i * 8, &data, 8);
	} 

	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return;
	}

	long real_loc = location - 0x400000;

	count = cs_disasm(handle, &(((unsigned char *)raw_file)[real_loc]), length, location, 0, &insn);
	if (count) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("    ");
			if (*insn[j].bytes == 0xE8){
				// Yes this is bad.
				printf(DGR"0x%"PRIx64 GRN":\t%s\t%s"RESET, insn[j].address, insn[j].mnemonic, insn[j].op_str);
				char call_address[100] = {0};
				sscanf(&insn[j].op_str[2], "%s", call_address); 

				printf(" <%s>", search_funcs_by_addr(fd, eh, sh_table, strtoul(call_address, NULL, 16)));

			// For printing nice colors.
			} else if (*insn[j].bytes == 0x55){
				printf(DGR"0x%"PRIx64 GRN":"CYN"\t%s"WHT"\t%s"RESET, insn[j].address, insn[j].mnemonic, insn[j].op_str);
			} else if (*insn[j].bytes == 0x5D){
				printf(DGR"0x%"PRIx64 GRN":"MAG"\t%s"WHT"\t%s"RESET, insn[j].address, insn[j].mnemonic, insn[j].op_str);
			} else if (*insn[j].bytes == 0xC3){
				printf(DGR"0x%"PRIx64 GRN":"RED"\t%s"WHT"\t%s"RESET, insn[j].address, insn[j].mnemonic, insn[j].op_str);
			}
			else {
				printf(DGR"0x%"PRIx64 WHT":\t%s\t%s"RESET, insn[j].address, insn[j].mnemonic, insn[j].op_str);
			}
			// Print where rip is.
			if (insn[j].address == rip){
				printf(RED" <-- rip"RESET);
			} 
			// This is loading a string for printf. Let's print that string.
			if (*(insn[j].bytes+1) == 0xbf && *(insn[j].bytes) == 0x48){
				uint32_t address = (*(insn[j].bytes+5) << 3 * 8) + (*(insn[j].bytes+4) << 2 * 8) + (*(insn[j].bytes+3) << 1 * 8) + (*(insn[j].bytes+2));
				// Get 24 chars out.
				char *string = malloc(40);
				for (int i = 0; i < 5; i++){
					long data = ptrace(PTRACE_PEEKTEXT, pid, address + 8 * i, 0);
					memcpy(string + i * 8, &data, 8);
				}

				// Clean up string.
				string[39] = '\0';
				strtok(string, "\n");
				printf(DRED" ;%s", string);
				free(string);
			}
			printf("\n"WHT);

		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

	//free(code);

    return;
}

void hex(pid_t pid, int length, long location, int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[], long rip, char *raw_file){
	long real_loc = location - 0x400000;
	for (int i = 0; i < length; i+=16){
		printf(DGR"%016lx: ", location + i);		

		for (int s = 0; s < 8; s++){
			printf(WHT"%02x" , (uint8_t)raw_file[i + real_loc + s*2]);
			printf(WHT"%02x ", (uint8_t)raw_file[i + real_loc + s*2+1]);
		}

		for (int s = 0; s < 16; s++){
			if (isprint((uint8_t)raw_file[i + real_loc + s])){
				putchar((uint8_t)raw_file[i + real_loc + s]);
			} else {
				putchar('.');
			}			
		}		
		printf("\n");
	}
}

void cont(pid_t pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head) {
	int status;
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(&status); 
	if (WIFEXITED(status)) {
		printf("[!] Program exited, returned %d.\n", WEXITSTATUS(status));
		*tracee_status = not_running;
		return;
	} else {
		int number;
		*tracee_status = at_break;
		ptrace(PTRACE_GETREGS, pid, 0, regs);
		struct breakpoint *curr = find_breakpoint(regs->rip - 1, bp_head, &number);
		printf(CYN"[!] Breakpoint %d hit.\n", number);
		unset_breakpoint(pid, curr->address, curr->old_data);
		ptrace(PTRACE_GETREGS, pid, 0, regs);
	}
}
void cont_ss(pid_t pid, struct user_regs_struct *regs, int *tracee_status, struct head *bp_head) {
	int status;
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	wait(&status); 
	*tracee_status = at_break;
	ptrace(PTRACE_GETREGS, pid, 0, regs);
}

struct breakpoint *add_breakpoint(long long unsigned int address, struct head *bp_head){
	printf(CYN"[!] Break set at 0x%llx\n", address);	
	struct breakpoint *new = malloc(sizeof(struct breakpoint));
	new->next = NULL;
	new->address = address;

	if (bp_head->list == NULL){
		bp_head->list = new;		
	} else {
		struct breakpoint *curr = bp_head->list;
		while (curr->next != NULL) {
			curr = curr->next;
		} 
		curr->next = new;
	}
	return new;

}

struct breakpoint *find_breakpoint(long long unsigned int address, struct head *bp_head, int *num){
	if (bp_head->list == NULL){
		return NULL;
	}
	int number = 1;
	struct breakpoint *curr = bp_head->list;
	while (curr != NULL) {
		if (curr->address == address) {
			*num = number;
			return curr;
		}
		number++;
		curr = curr->next;
	} 
	return NULL;
}

long set_breakpoint(pid_t pid, long addr){
	long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);
	long stored_data = data;

	// Add int3 to address.
	data = (data & ~0xff) | 0xcc;
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, data);

	return stored_data;	
}

void set_all_breaks(pid_t pid, struct head *bp_head){
	
	struct breakpoint *curr = bp_head->list;

	while(curr != NULL){
		curr->old_data = set_breakpoint(pid, curr->address);
		curr = curr->next;
	}
}

void set_rip(pid_t pid, long addr) {
  struct user_regs_struct regs;
  memset(&regs, 0, sizeof(regs));
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  regs.rip = addr;
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

void unset_breakpoint(pid_t pid, long addr, long old_data){
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, old_data);
	set_rip(pid, addr);
}

// Printing functions.
void print_registers(struct user_regs_struct *regs){
	printf(RED"rax:"DGR"  %llx\n", regs->rax);
	printf(RED"rbx:"DGR"  %llx\n", regs->rbx);
	printf(RED"rcx:"DGR"  %llx\n", regs->rcx);
	printf(RED"rdx:"DGR"  %llx\n", regs->rdx);
	printf(RED"rsp:"DGR"  %llx\n", regs->rsp);
	printf(RED"rbp:"DGR"  %llx\n", regs->rbp);
	printf(RED"rsi:"DGR"  %llx\n", regs->rsi);
	printf(RED"rdi:"DGR"  %llx\n", regs->rdi);
	printf(RED"rip:"DGR"  %llx\n", regs->rip);
	printf(RED"r8 :"DGR"  %llx\n", regs->r8);
	printf(RED"r9 :"DGR"  %llx\n", regs->r9);
	printf(RED"r10:"DGR"  %llx\n", regs->r10);
	printf(RED"r11:"DGR"  %llx\n", regs->r11);
	printf(RED"r12:"DGR"  %llx\n", regs->r12);
	printf(RED"r13:"DGR"  %llx\n", regs->r13);
	printf(RED"r14:"DGR"  %llx\n", regs->r14);
	printf(RED"r15:"DGR"  %llx\n", regs->r15);
}

void print_stack(pid_t pid, long sp, long amount){
	// Print first with arrow for rsp then loop through desired amount.
	long data = ptrace(PTRACE_PEEKTEXT, pid, (long *)sp, 0);
	printf(DGR"0x%lx |"WHT" 0x%lx <-- $rsp\n", sp, data);
	for (int i = 1; i < amount; i++){
		data = ptrace(PTRACE_PEEKTEXT, pid, (long *)sp + i, 0);
		printf(DGR"0x%lx |"WHT" 0x%lx\n", sp + i * 8, data);
	}
}

void print_all_breaks(struct head *bp_head){
	
	struct breakpoint *curr = bp_head->list;
	int i = 1;
	while(curr != NULL){
		printf("%d: 0x%llx\n", i, curr->address);
		curr = curr->next;
		i++;
	}
}