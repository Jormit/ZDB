#pragma once

#include <elf.h>
#include <stdbool.h>

#define DEBUG 1

#define debug(...)                                                             \
  do {                                                                         \
    if (DEBUG)                                                                 \
      printf("<debug>:"__VA_ARGS__);                                           \
  } while (0)

struct search_term {
  long address;
  long size;
};

// Checking elf.
bool is_ELF64(Elf64_Ehdr eh);

// Header functions.
void read_elf_header64(int32_t fd, Elf64_Ehdr *elf_header);
void print_elf_header64(Elf64_Ehdr elf_header);
void read_section_header_table64(int32_t fd, Elf64_Ehdr eh,
                                 Elf64_Shdr sh_table[]);

// Section functions.
char *read_section64(int32_t fd, Elf64_Shdr sh);
void print_section_headers64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]);

// Symbol functions.
void print_symbol_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                          uint32_t symbol_table);
void print_symbols64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]);
void print_rela_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]);

// Searching For functions by name.
struct search_term search_funcs64(int32_t fd, Elf64_Ehdr eh,
                                  Elf64_Shdr sh_table[], char *query);
struct search_term search_func_table64(int32_t fd, Elf64_Ehdr eh,
                                       Elf64_Shdr sh_table[],
                                       uint32_t symbol_table, char *query);

// Searching for functions by address (uses plt stub address for dynamic
// functions).
char *search_func_tbl_by_addr(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                              uint32_t symbol_table, uint32_t plt_table,
                              Elf64_Addr plt_mem, long search_addr);
char *search_funcs_by_addr(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                           long search_addr);

// Print out functions and .plt and .got addresses.
void print_func_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                        uint32_t symbol_table, uint32_t plt_table,
                        Elf64_Addr plt_mem);
void print_funcs64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]);
