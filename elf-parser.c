#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "colors.h"
#include "elf-parser.h"

void read_elf_header64(int32_t fd, Elf64_Ehdr *elf_header) {
  assert(elf_header != NULL);
  assert(lseek(fd, (off_t)0, SEEK_SET) == (off_t)0);
  assert(read(fd, (void *)elf_header, sizeof(Elf64_Ehdr)) ==
         sizeof(Elf64_Ehdr));
}

bool is_ELF64(Elf64_Ehdr eh) {
  /* ELF magic bytes are 0x7f,'E','L','F'
   * Using  octal escape sequence to represent 0x7f
   */
  if (!strncmp((char *)eh.e_ident, "\177ELF", 4)) {
    /* IS a ELF file */
    return 1;
  } else {
    printf("ELFMAGIC mismatch!\n");
    /* Not ELF file */
    return 0;
  }
}

void print_elf_header64(Elf64_Ehdr elf_header) {

  /* Storage capacity class */
  printf("Storage class\t= ");
  switch (elf_header.e_ident[EI_CLASS]) {
  case ELFCLASS32:
    printf("32-bit objects\n");
    break;

  case ELFCLASS64:
    printf("64-bit objects\n");
    break;

  default:
    printf("INVALID CLASS\n");
    break;
  }

  /* Data Format */
  printf("Data format\t= ");
  switch (elf_header.e_ident[EI_DATA]) {
  case ELFDATA2LSB:
    printf("2's complement, little endian\n");
    break;

  case ELFDATA2MSB:
    printf("2's complement, big endian\n");
    break;

  default:
    printf("INVALID Format\n");
    break;
  }

  /* OS ABI */
  printf("OS ABI\t\t= ");
  switch (elf_header.e_ident[EI_OSABI]) {
  case ELFOSABI_SYSV:
    printf("UNIX System V ABI\n");
    break;

  case ELFOSABI_HPUX:
    printf("HP-UX\n");
    break;

  case ELFOSABI_NETBSD:
    printf("NetBSD\n");
    break;

  case ELFOSABI_LINUX:
    printf("Linux\n");
    break;

  case ELFOSABI_SOLARIS:
    printf("Sun Solaris\n");
    break;

  case ELFOSABI_AIX:
    printf("IBM AIX\n");
    break;

  case ELFOSABI_IRIX:
    printf("SGI Irix\n");
    break;

  case ELFOSABI_FREEBSD:
    printf("FreeBSD\n");
    break;

  case ELFOSABI_TRU64:
    printf("Compaq TRU64 UNIX\n");
    break;

  case ELFOSABI_MODESTO:
    printf("Novell Modesto\n");
    break;

  case ELFOSABI_OPENBSD:
    printf("OpenBSD\n");
    break;

  case ELFOSABI_ARM_AEABI:
    printf("ARM EABI\n");
    break;

  case ELFOSABI_ARM:
    printf("ARM\n");
    break;

  case ELFOSABI_STANDALONE:
    printf("Standalone (embedded) app\n");
    break;

  default:
    printf("Unknown (0x%x)\n", elf_header.e_ident[EI_OSABI]);
    break;
  }

  /* ELF filetype */
  printf("Filetype \t= ");
  switch (elf_header.e_type) {
  case ET_NONE:
    printf("N/A (0x0)\n");
    break;

  case ET_REL:
    printf("Relocatable\n");
    break;

  case ET_EXEC:
    printf("Executable\n");
    break;

  case ET_DYN:
    printf("Shared Object\n");
    break;
  default:
    printf("Unknown (0x%x)\n", elf_header.e_type);
    break;
  }

  /* ELF Machine-id */
  printf("Machine\t\t= ");
  switch (elf_header.e_machine) {
  case EM_NONE:
    printf("None (0x0)\n");
    break;

  case EM_386:
    printf("INTEL x86 (0x%x)\n", EM_386);
    break;

  case EM_X86_64:
    printf("AMD x86_64 (0x%x)\n", EM_X86_64);
    break;

  case EM_AARCH64:
    printf("AARCH64 (0x%x)\n", EM_AARCH64);
    break;

  default:
    printf(" 0x%x\n", elf_header.e_machine);
    break;
  }

  /* Entry point */
  printf("Entry point\t= 0x%08lx\n", elf_header.e_entry);

  /* ELF header size in bytes */
  printf("ELF header size\t= 0x%08x\n", elf_header.e_ehsize);
}

void read_section_header_table64(int32_t fd, Elf64_Ehdr eh,
                                 Elf64_Shdr sh_table[]) {
  uint32_t i;

  assert(lseek(fd, (off_t)eh.e_shoff, SEEK_SET) == (off_t)eh.e_shoff);

  for (i = 0; i < eh.e_shnum; i++) {
    assert(read(fd, (void *)&sh_table[i], eh.e_shentsize) == eh.e_shentsize);
  }
}

char *read_section64(int32_t fd, Elf64_Shdr sh) {
  char *buff = malloc(sh.sh_size);
  if (!buff) {
    printf("%s:Failed to allocate %ldbytes\n", __func__, sh.sh_size);
  }

  assert(buff != NULL);
  assert(lseek(fd, (off_t)sh.sh_offset, SEEK_SET) == (off_t)sh.sh_offset);
  assert(read(fd, (void *)buff, sh.sh_size) == sh.sh_size);

  return buff;
}

void print_section_headers64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
  uint32_t i;
  char *sh_str; /* section-header string-table is also a section. */

  /* Read section-header string-table */
  sh_str = read_section64(fd, sh_table[eh.e_shstrndx]);

  printf(CYN "load-addr  size       section\n");

  for (i = 0; i < eh.e_shnum; i++) {
    printf(DGR "0x%08lx ", sh_table[i].sh_addr);
    printf(DGR "0x%08lx | ", sh_table[i].sh_size);
    printf(WHT "%s\t", (sh_str + sh_table[i].sh_name));
    printf("\n");
  } /* end of section header table */
}

void print_rela_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
  uint32_t rela_tbl_index = 0;                          
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_RELA) {
      rela_tbl_index = i;
    }
  }
  Elf64_Rela *rela_tbl = (Elf64_Rela *)read_section64(fd, sh_table[rela_tbl_index]);
  uint32_t dynsym_index = 0;
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_DYNSYM) {
      dynsym_index = i;
      break;
    }
  }
  Elf64_Sym *dynsym_tbl = (Elf64_Sym *)read_section64(fd, sh_table[dynsym_index]);
  char *str_tbl = read_section64(fd, sh_table[sh_table[dynsym_index].sh_link]);
  uint32_t symbol_count = (sh_table[rela_tbl_index].sh_size / sizeof(Elf64_Rela));

  printf("%u\n", symbol_count);

  for (uint32_t i = 0; i < symbol_count; i++) {
       printf("0x%08lx ", rela_tbl[i].r_offset);
       printf("%s\n", (str_tbl + dynsym_tbl[ELF64_R_SYM (rela_tbl[i].r_info)].st_name));
  }
}

void print_syms_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
  uint32_t syms_tbl_index = 0;                          
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB) {
      syms_tbl_index = i;
    }
  }
  Elf64_Sym *syms_tbl = (Elf64_Sym *)read_section64(fd, sh_table[syms_tbl_index]);
  char *str_tbl = read_section64(fd, sh_table[sh_table[syms_tbl_index].sh_link]);
  uint32_t symbol_count = (sh_table[syms_tbl_index].sh_size / sizeof(Elf64_Rela));

  for (uint32_t i = 0; i < symbol_count; i++) {
       uint32_t name_index = syms_tbl[i].st_name;
       if (name_index) {
        printf("0x%08lx ", syms_tbl[i].st_value);
        printf("%s\n", (str_tbl + name_index));
       }
  }
}

void print_dynsyms_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
  uint32_t dynsyms_tbl_index = 0;                          
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_DYNSYM) {
      dynsyms_tbl_index = i;
    }
  }
  Elf64_Sym *dynsyms_tbl = (Elf64_Sym *)read_section64(fd, sh_table[dynsyms_tbl_index]);
  char *str_tbl = read_section64(fd, sh_table[sh_table[dynsyms_tbl_index].sh_link]);
  uint32_t symbol_count = (sh_table[dynsyms_tbl_index].sh_size / sizeof(Elf64_Rela));

  for (uint32_t i = 0; i < symbol_count; i++) {
       uint32_t name_index = dynsyms_tbl[i].st_name;
       if (name_index) {
        printf("0x%08lx ", dynsyms_tbl[i].st_value);
        printf("%s\n", (str_tbl + name_index));
       }
  }
}

void print_symbol_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                          uint32_t symbol_table) {
  char *str_tbl;
  Elf64_Sym *sym_tbl;
  uint32_t i, symbol_count;

  sym_tbl = (Elf64_Sym *)read_section64(fd, sh_table[symbol_table]);

  uint32_t str_tbl_ndx = sh_table[symbol_table].sh_link;
  str_tbl = read_section64(fd, sh_table[str_tbl_ndx]);

  symbol_count = (sh_table[symbol_table].sh_size / sizeof(Elf64_Sym));

  for (i = 0; i < symbol_count; i++) {
    if (ELF32_ST_TYPE(sym_tbl[i].st_info) == 0x3) {
      continue;
    }
    printf("0x%08lx ", sym_tbl[i].st_value);
    printf("%s\n", (str_tbl + sym_tbl[i].st_name));
  }
}

void print_symbols64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB ||
        sh_table[i].sh_type == SHT_DYNSYM) {
      print_symbol_table64(fd, eh, sh_table, i);
    }
  }
}

// Print functions nicely.
void print_func_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                        uint32_t symbol_table, uint32_t plt_table,
                        Elf64_Addr plt_mem) {
  char *str_tbl;
  Elf64_Rela *plt_tbl;
  uint32_t i, symbol_count, plt_count;
  Elf64_Sym *sym_tbl;
  int plt_offset = 0;

  sym_tbl = (Elf64_Sym *)read_section64(fd, sh_table[symbol_table]);

  if (plt_table != 0) {
    plt_tbl = (Elf64_Rela *)read_section64(fd, sh_table[plt_table]);
  }

  uint32_t str_tbl_ndx = sh_table[symbol_table].sh_link;
  str_tbl = read_section64(fd, sh_table[str_tbl_ndx]);

  plt_count = (sh_table[plt_table].sh_size / sizeof(Elf64_Rela));
  symbol_count = (sh_table[symbol_table].sh_size / sizeof(Elf64_Sym));

  if (plt_table) {
    printf(CYN "\n.got       .plt         symbol_name\n");
  } else {
    printf(CYN "\naddress      symbol_name\n");
  }

  for (i = 0; i < symbol_count; i++) {
    if (ELF32_ST_TYPE(sym_tbl[i].st_info) != STT_FUNC) {
      continue;
    } else if (plt_table == 0 && sym_tbl[i].st_value == 0x0) {
      continue;
    }
    if (plt_table == 0) {
      printf(DGR "0x%08lx | ", sym_tbl[i].st_value);
    }
    if (plt_table != 0 && plt_offset < plt_count && i > 0 &&
        ((ELF64_R_SYM(plt_tbl[plt_offset].r_info) == i))) {
      printf(DGR "0x%08lx ", plt_tbl[plt_offset].r_offset);
      printf(DGR "0x%08lx | ", plt_mem + (int)(16 * (plt_offset + 1)));
      plt_offset++;
    } else if (plt_table != 0) {
      continue;
    }
    printf(WHT "%s\n", (str_tbl + sym_tbl[i].st_name));
  }
}

// Print functions nicely.
void print_funcs64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[]) {
  uint32_t i;
  int plt_rela_table = 0;
  Elf64_Addr plt_address = 0;
  char *sh_str = read_section64(fd, sh_table[eh.e_shstrndx]);

  // Find where rela.plt and .plt is.
  for (i = 0; i < eh.e_shnum; i++) {
    if ((sh_table[i].sh_type == SHT_RELA && sh_table[i].sh_info)) {
      plt_rela_table = i;
    }
    if (strcmp((sh_str + sh_table[i].sh_name), ".plt") == 0) {
      plt_address = sh_table[i].sh_addr;
    }
  }
  // Print dynsyms and symtab.
  for (i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB) {
      printf("\n[User Defined Functions] ");
      print_func_table64(fd, eh, sh_table, i, 0, 0);
    } else if (sh_table[i].sh_type == SHT_DYNSYM) {
      printf("[Dynamic Functions] ");
      print_func_table64(fd, eh, sh_table, i, plt_rela_table, plt_address);
    }
  }
}

// Actually wtf pls kill me.
char *search_func_tbl_by_addr(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                              uint32_t symbol_table, uint32_t plt_table,
                              Elf64_Addr plt_mem, long search_addr) {

  char *str_tbl;
  Elf64_Rela *plt_tbl;
  uint32_t i, symbol_count, plt_count;
  Elf64_Sym *sym_tbl;
  int plt_offset = 0;

  sym_tbl = (Elf64_Sym *)read_section64(fd, sh_table[symbol_table]);

  if (plt_table != 0) {
    plt_tbl = (Elf64_Rela *)read_section64(fd, sh_table[plt_table]);
  }

  uint32_t str_tbl_ndx = sh_table[symbol_table].sh_link;
  // debug("str_table_ndx = 0x%x\n", str_tbl_ndx);
  str_tbl = read_section64(fd, sh_table[str_tbl_ndx]);

  plt_count = (sh_table[plt_table].sh_size / sizeof(Elf64_Rela));
  symbol_count = (sh_table[symbol_table].sh_size / sizeof(Elf64_Sym));

  for (i = 0; i < symbol_count; i++) {
    if (ELF32_ST_TYPE(sym_tbl[i].st_info) != STT_FUNC) {
      continue;
    } else if (plt_table == 0 && sym_tbl[i].st_value == 0x0) {
      continue;
    }
    if (plt_table == 0) {
      if (search_addr == sym_tbl[i].st_value) {
        return (str_tbl + sym_tbl[i].st_name);
      }
    }
    if (plt_table != 0 && plt_offset < plt_count && i > 0 &&
        ((ELF64_R_SYM(plt_tbl[plt_offset].r_info) == i))) {
      if (plt_mem + (int)(16 * (plt_offset + 1)) == search_addr) {
        return (str_tbl + sym_tbl[i].st_name);
      }
      plt_offset++;
    }
  }
  return NULL;
}

// Find func name from address (include linked functions)
char *search_funcs_by_addr(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                           long search_addr) {
  uint32_t i;
  int plt_rela_table = 0;
  Elf64_Addr plt_address = 0;
  char *sh_str = read_section64(fd, sh_table[eh.e_shstrndx]);

  // Find where rela.plt and .plt is.
  for (i = 0; i < eh.e_shnum; i++) {
    if ((sh_table[i].sh_type == SHT_RELA && sh_table[i].sh_info)) {
      plt_rela_table = i;
    }
    if (strcmp((sh_str + sh_table[i].sh_name), ".plt") == 0) {
      plt_address = sh_table[i].sh_addr;
    }
  }
  // Search dynsyms and symtab.
  for (i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB) {
      char *result =
          search_func_tbl_by_addr(fd, eh, sh_table, i, 0, 0, search_addr);
      if (result != NULL) {
        return result;
      }
    } else if (sh_table[i].sh_type == SHT_DYNSYM) {
      char *result = search_func_tbl_by_addr(
          fd, eh, sh_table, i, plt_rela_table, plt_address, search_addr);
      if (result != NULL) {
        return result;
      }
    }
  }
  return NULL;
}

// Search user functions by name.
struct search_term search_funcs64(int32_t fd, Elf64_Ehdr eh,
                                  Elf64_Shdr sh_table[], char *query) {
  uint32_t i;
  struct search_term result;
  result.size = 0;
  result.address = 0;

  for (i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB) {
      struct search_term result =
          search_func_table64(fd, eh, sh_table, i, query);
      if (result.size != 0) {
        return result;
      }
    }
  }
  return result;
}

// Search user func table by name.
struct search_term search_func_table64(int32_t fd, Elf64_Ehdr eh,
                                       Elf64_Shdr sh_table[],
                                       uint32_t symbol_table, char *query) {
  char *str_tbl;
  Elf64_Sym *sym_tbl;
  uint32_t i, symbol_count;
  struct search_term result;

  result.size = 0;
  result.address = 0;

  sym_tbl = (Elf64_Sym *)read_section64(fd, sh_table[symbol_table]);

  uint32_t str_tbl_ndx = sh_table[symbol_table].sh_link;
  str_tbl = read_section64(fd, sh_table[str_tbl_ndx]);

  symbol_count = (sh_table[symbol_table].sh_size / sizeof(Elf64_Sym));

  for (i = 0; i < symbol_count; i++) {
    if (strcmp((str_tbl + sym_tbl[i].st_name), query) == 0) {
      result.address = sym_tbl[i].st_value;
      result.size = sym_tbl[i].st_size;
      return result;
    }
  }
  return result;
}
