#pragma once

#include <elf.h>
#include <stdbool.h>

#define DEBUG 1

#define debug(...)                                                             \
  do {                                                                         \
    if (DEBUG)                                                                 \
      printf("<debug>:"__VA_ARGS__);                                           \
  } while (0)

struct search_result {
  Elf64_Addr address;
  uint64_t size;
  char *name;
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

// Table Printing Functions
void print_section_headers64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]);

void print_rela_tables64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                         unsigned char type);
void print_syms_tables64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                         unsigned char type);
void print_dynsyms_tables64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                            unsigned char type);

void print_rela_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                        unsigned char type, uint32_t rela_tbl_index);
void print_syms_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                        unsigned char type, uint32_t syms_tbl_index);

// Searching Functions
struct search_result search_syms_table64(int32_t fd, Elf64_Ehdr eh,
                                         Elf64_Shdr sh_table[],
                                         Elf64_Addr address, char *name);
struct search_result search_rela_table64(int32_t fd, Elf64_Ehdr eh,
                                         Elf64_Shdr sh_table[],
                                         Elf64_Addr address, char *name);
