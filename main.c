#include "colors.h"
#include "debugger.h"
#include "elf-parser.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int terminal(char *argv[]);
int open_for_analysis(int32_t *fd, char *argv[]);
void print_banner();
int parse_option(char *argument);
void print_help();
char *get_raw(char *argv[]);

// Defines for options.
#define RUN 0
#define QUIT 1
#define CONT 2
#define STEP 3
#define STACK 4
#define REGS 5
#define SHOW_BREAKS 6
#define SET_BREAK 7
#define HEADER 8
#define SYMBOLS 9
#define SECTIONS 10
#define FUNCTIONS 11
#define HELP 12
#define INVALID 13
#define DISAS 14
#define HEX 15
#define RELA 16

int main(int argc, char *argv[]) {
  // Must have a program to execute on.
  if (argc == 1) {
    printf("Usage: ./debugger program args...\n");
    return 1;
  }
  // Start the main terminal.
  terminal(argv);
}

int terminal(char *argv[]) {
  char argument[100];
  int tracee_status = not_running;
  struct user_regs_struct regs;
  pid_t pid;
  struct head bp_head;
  bp_head.list = NULL;

  // Needed to open elf for analysis.
  int32_t fd;
  Elf64_Ehdr eh;
  Elf64_Shdr *sh_tbl;

  // Open up the raw file used for disas.
  char *raw_file = get_raw(argv);
  if (raw_file == NULL) {
    printf(CYN "[x] Could not open file.\n");
  }

  // If file exists get pointer to it for elf analysis.
  if (open_for_analysis(&fd, argv)) {
  } else {
    return 1;
  }

  // We only debug 64 bit
  read_elf_header64(fd, &eh);
  if (is_ELF64(eh)) {
    sh_tbl = malloc(eh.e_shentsize * eh.e_shnum);
    read_section_header_table64(fd, eh, sh_tbl);

  } else {
    printf(CYN "[x] Elf file is not 64 bits.\n");
    return 1;
  }

  // Everything is ok -_-
  // Lets start.
  print_banner();

  run(argv, &pid, &regs, &tracee_status, &bp_head);
  while (1) {
    if (tracee_status == not_running) {
      printf(WHT "[0x00000000]> ");
    } else if (tracee_status == at_break) {
      printf(WHT "[0x%llx]> ", regs.rip);
    }

    // Read in argument.
    fgets(argument, 100, stdin);
    strtok(argument, "\n");

    char command[100];

    sscanf(argument, "%s ", command);

    struct search_term result;

    char *ptr;
    long number = 0;
    char amount[100] = {0};

    struct breakpoint *new;

    switch (parse_option(command)) {
    case RUN:
      run(argv, &pid, &regs, &tracee_status, &bp_head);
      cont(pid, &regs, &tracee_status, &bp_head);
      break;

    case QUIT:
      kill(pid, SIGKILL);
      exit(1);
      break;

    case CONT:
      if (tracee_status == not_running) {
        printf(CYN "[x] Process not started yet. \n");
      } else {
        cont(pid, &regs, &tracee_status, &bp_head);
      }
      // run(argv, &pid, &regs, &tracee_status, &bp_head);
      break;

    case STEP:
      cont_ss(pid, &regs, &tracee_status, &bp_head);
      break;

    case STACK:
      sscanf(argument, "%*s %s", amount);
      number = strtoul(amount, &ptr, 10);
      if (number != 0) {
        print_stack(pid, regs.rsp, number);
      } else {
        print_stack(pid, regs.rsp, 10);
      }
      break;

    case REGS:
      print_registers(&regs);
      break;

    case SHOW_BREAKS:
      print_all_breaks(&bp_head);
      break;

    case SET_BREAK:
      if (sscanf(argument, "%*s %s", amount) == EOF) {
        printf(CYN "[!] Memory address/function required.\n");
        break;
      }
      number = strtoul(amount, &ptr, 16);
      if (!number) {
        result = search_funcs64(fd, eh, sh_tbl, amount);
        if (result.size != 0) {
          new = add_breakpoint(result.address, &bp_head);
          new->old_data = set_breakpoint(pid, result.address);
        } else {
          printf(CYN "[!] Invalid address/function.\n");
        }

      } else {
        new = add_breakpoint(number, &bp_head);
        new->old_data = set_breakpoint(pid, number);
      }
      break;

    case DISAS:
      if (sscanf(argument, "%*s %s", amount) == EOF) {
        if (tracee_status == not_running) {
          printf(CYN "[!] Can't disassemble here!\n");
        } else {
          disas(pid, 0x30, regs.rip, fd, eh, sh_tbl, regs.rip, raw_file);
        }
      } else {
        number = strtoul(amount, &ptr, 16);
        if (number == 0) {
          sscanf(argument, "%*s %s", amount);
          result = search_funcs64(fd, eh, sh_tbl, amount);
          if (result.size != 0) {
            printf(RESET CYN "Disassembly of %s\n", amount);
            disas(pid, result.size, result.address, fd, eh, sh_tbl, regs.rip,
                  raw_file);
          } else {
            printf(CYN "[!] Invalid address/function.\n");
          }
        } else {
          disas(pid, 0x80, number, fd, eh, sh_tbl, regs.rip, raw_file);
        }
      }
      break;

    case HEX:
      if (sscanf(argument, "%*s %s", amount) == EOF) {
        if (tracee_status == not_running) {
          printf(CYN "[!] Can't disassemble here!\n");
        } else {
          hex(pid, 0x30, regs.rip, fd, eh, sh_tbl, regs.rip, raw_file);
        }
      } else {
        number = strtoul(amount, &ptr, 16);
        if (!number) {
          sscanf(argument, "%*s %s", amount);
          result = search_funcs64(fd, eh, sh_tbl, amount);
          if (result.size != 0) {
            printf(RESET CYN "Hexdump of %s\n", amount);
            hex(pid, result.size, result.address, fd, eh, sh_tbl, regs.rip,
                raw_file);
          } else {
            printf(CYN "[!] Invalid address/function.\n");
          }
        } else {
          hex(pid, 0x80, number, fd, eh, sh_tbl, regs.rip, raw_file);
        }
      }
      break;

    case HEADER:
      print_elf_header64(eh);
      break;

    case SYMBOLS:
      print_syms_table64(fd, eh, sh_tbl);
      break;

    case SECTIONS:
      print_section_headers64(fd, eh, sh_tbl);
      break;

    case FUNCTIONS:
      print_funcs64(fd, eh, sh_tbl);
      break;

    case HELP:
      print_help();
      break;

    case RELA:
      print_rela_table64(fd, eh, sh_tbl);
      break;

    case INVALID:
      printf(CYN "[x] Invalid command\n");
      break;
    }
  }
}

int parse_option(char *argument) {
  // Compare arguments.
  if (strcmp(argument, "r") == 0) {
    return RUN;
  } else if (strcmp(argument, "q") == 0) {
    return QUIT;
  } else if (strcmp(argument, "c") == 0) {
    return CONT;
  } else if (strcmp(argument, "s") == 0) {
    return STEP;
  } else if (strcmp(argument, "stack") == 0) {
    return STACK;
  } else if (strcmp(argument, "regs") == 0) {
    return REGS;
  } else if (strcmp(argument, "breaks") == 0) {
    return SHOW_BREAKS;
  } else if (strcmp(argument, "b") == 0) {
    return SET_BREAK;
  } else if (strcmp(argument, "header") == 0) {
    return HEADER;
  } else if (strcmp(argument, "symb") == 0) {
    return SYMBOLS;
  } else if (strcmp(argument, "sect") == 0) {
    return SECTIONS;
  } else if (strcmp(argument, "func") == 0) {
    return FUNCTIONS;
  } else if (strcmp(argument, "help") == 0) {
    return HELP;
  } else if (strcmp(argument, "disas") == 0) {
    return DISAS;
  } else if (strcmp(argument, "hex") == 0) {
    return HEX;
  } else if (strcmp(argument, "rela") == 0) {
    return RELA;
  } else {
    return INVALID;
  }
}

int open_for_analysis(int32_t *fd, char *argv[]) {
  *fd = open(argv[1], O_RDONLY | O_SYNC);

  if (fd < 0) {
    printf("[x] Unable to open %s\n", argv[1]);
    return 0;
  }

  return 1;
}

void print_banner() {
  printf(WHT "	_ _     \n");
  printf("       | | |    \n");
  printf(" ______| | |__  \n");
  printf("|_  / _` | '_ \\ \n");
  printf(" / / (_| | |_) |\n");
  printf("/___\\__,_|_.__/ \n");
  printf(GRN "Type \"help\" for more info.\n");
  return;
}

void print_help() {
  printf(DGR "zdb - A simple 64 bit elf debugger.\n");
  printf(GRN "Commands:\n");
  printf(GRN "r" DGR "                 - starts/restarts execution.\n");
  printf(GRN
         "c" DGR
         "                 - continues execution until end or breakpoint.\n");
  printf(GRN "b [addr/func]" DGR "     - sets break at specified address.\n");
  printf(GRN "breaks" DGR "            - shows set breakpoints.\n");
  printf(GRN "stack [amount]" DGR
             "    - displays stackdump of [amount] length.\n");
  printf(GRN "regs" DGR "              - displays register values.\n");
  printf(GRN "sect" DGR "              - displays elf sections.\n");
  printf(GRN "func" DGR "              - displays binary functions.\n");
  printf(GRN "disas [func/addr]" DGR
             " - displays disassembly of specified area.\n");
  printf(GRN "hex [func/addr]" DGR
             "   - displays hexdump of specified area.\n");
  printf(GRN "q" DGR "                 - quits program.\n");
  return;
}

char *get_raw(char *argv[]) {
  // Store the raw file.
  char *raw_file = NULL;
  FILE *f = fopen(argv[1], "rb");
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  raw_file = malloc(fsize + 1);
  fread(raw_file, 1, fsize, f);
  fclose(f);
  raw_file[fsize] = 0;
  return raw_file;
}