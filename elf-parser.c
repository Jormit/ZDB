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
  if (!strncmp((char *)eh.e_ident, "\177ELF", 4)) {
    return 1;
  } else {
    printf("ELFMAGIC mismatch!\n");
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
  assert(lseek(fd, (off_t)eh.e_shoff, SEEK_SET) == (off_t)eh.e_shoff);
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
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
  char *sh_str = read_section64(fd, sh_table[eh.e_shstrndx]);
  printf(CYN "load-addr  size       section\n");
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    printf(DGR "0x%08lx ", sh_table[i].sh_addr);
    printf(DGR "0x%08lx | ", sh_table[i].sh_size);
    printf(WHT "%s\t", (sh_str + sh_table[i].sh_name));
    printf("\n");
  }
  free(sh_str);
}

void print_rela_tables64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                         unsigned char type) {
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_RELA) {
      print_rela_table64(fd, eh, sh_table, type, i);
    }
  }
}

void print_rela_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                        unsigned char type, uint32_t rela_tbl_index) {
  Elf64_Rela *rela_tbl =
      (Elf64_Rela *)read_section64(fd, sh_table[rela_tbl_index]);
  uint32_t dynsym_index = 0;
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_DYNSYM) {
      dynsym_index = i;
      break;
    }
  }
  Elf64_Sym *dynsym_tbl =
      (Elf64_Sym *)read_section64(fd, sh_table[dynsym_index]);
  char *str_tbl = read_section64(fd, sh_table[sh_table[dynsym_index].sh_link]);
  uint32_t symbol_count =
      (sh_table[rela_tbl_index].sh_size / sizeof(Elf64_Rela));

  for (uint32_t i = 0; i < symbol_count; i++) {
    uint32_t name_index = dynsym_tbl[ELF64_R_SYM(rela_tbl[i].r_info)].st_name;
    unsigned char sym_type =
        ELF64_ST_TYPE(dynsym_tbl[ELF64_R_SYM(rela_tbl[i].r_info)].st_info);
    if (name_index && (type == STT_NOTYPE || type == sym_type)) {
      printf("0x%08lx ", rela_tbl[i].r_offset);
      printf("%s\n", str_tbl + name_index);
    }
  }

  free(rela_tbl);
  free(dynsym_tbl);
  free(str_tbl);
}

void print_syms_tables64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                         unsigned char type) {
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB) {
      print_syms_table64(fd, eh, sh_table, type, i);
    }
  }
}

void print_dynsyms_tables64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                            unsigned char type) {
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_DYNSYM) {
      print_syms_table64(fd, eh, sh_table, type, i);
    }
  }
}

void print_syms_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[],
                        unsigned char type, uint32_t syms_tbl_index) {
  Elf64_Sym *syms_tbl =
      (Elf64_Sym *)read_section64(fd, sh_table[syms_tbl_index]);
  char *str_tbl =
      read_section64(fd, sh_table[sh_table[syms_tbl_index].sh_link]);
  uint32_t symbol_count =
      (sh_table[syms_tbl_index].sh_size / sizeof(Elf64_Rela));

  for (uint32_t i = 0; i < symbol_count; i++) {
    uint32_t name_index = syms_tbl[i].st_name;
    unsigned char sym_type = ELF64_ST_TYPE(syms_tbl[i].st_info);
    if (name_index && (type == STT_NOTYPE || type == sym_type)) {
      printf("0x%08lx ", syms_tbl[i].st_value);
      printf("%s\n", (str_tbl + name_index));
    }
  }
  free(syms_tbl);
  free(str_tbl);
}

struct search_result search_syms_table64(int32_t fd, Elf64_Ehdr eh,
                                         Elf64_Shdr sh_table[],
                                         Elf64_Addr address, char *name) {
  uint32_t syms_tbl_index = 0;
  struct search_result ret = {.address = 0, .name = NULL, .size = 0};
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB) {
      syms_tbl_index = i;
    }
  }
  Elf64_Sym *syms_tbl =
      (Elf64_Sym *)read_section64(fd, sh_table[syms_tbl_index]);
  char *str_tbl =
      read_section64(fd, sh_table[sh_table[syms_tbl_index].sh_link]);
  uint32_t symbol_count =
      (sh_table[syms_tbl_index].sh_size / sizeof(Elf64_Rela));

  for (uint32_t i = 0; i < symbol_count; i++) {
    uint32_t name_index = syms_tbl[i].st_name;
    if (name_index && name != NULL && !strcmp(name, str_tbl + name_index)) {
      ret.address = syms_tbl[i].st_value;
      ret.size = syms_tbl[i].st_size;
      break;
    } else if (syms_tbl[i].st_value == address) {
      ret.address = syms_tbl[i].st_value;
      ret.name = malloc(strlen(str_tbl + name_index) * sizeof(char));
      strcpy(ret.name, str_tbl + name_index);
      ret.size = syms_tbl[i].st_size;
    }
  }
  free(syms_tbl);
  free(str_tbl);
  return ret;
}

struct search_result search_rela_table64(int32_t fd, Elf64_Ehdr eh,
                                         Elf64_Shdr sh_table[],
                                         Elf64_Addr address, char *name) {
  uint32_t rela_tbl_index = 0;
  struct search_result ret = {.address = 0, .name = NULL, .size = 0};
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_RELA) {
      rela_tbl_index = i;
    }
  }
  Elf64_Rela *rela_tbl =
      (Elf64_Rela *)read_section64(fd, sh_table[rela_tbl_index]);
  uint32_t dynsym_index = 0;
  for (uint32_t i = 0; i < eh.e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_DYNSYM) {
      dynsym_index = i;
      break;
    }
  }
  Elf64_Sym *dynsym_tbl =
      (Elf64_Sym *)read_section64(fd, sh_table[dynsym_index]);
  char *str_tbl = read_section64(fd, sh_table[sh_table[dynsym_index].sh_link]);
  uint32_t symbol_count =
      (sh_table[rela_tbl_index].sh_size / sizeof(Elf64_Rela));

  for (uint32_t i = 0; i < symbol_count; i++) {
    uint32_t name_index = dynsym_tbl[ELF64_R_SYM(rela_tbl[i].r_info)].st_name;
    if (name_index && name != NULL && !strcmp(name, str_tbl + name_index)) {
      ret.address = rela_tbl[i].r_offset;
      ret.size = dynsym_tbl[ELF64_R_SYM(rela_tbl[i].r_info)].st_size;
      break;
    } else if (rela_tbl[i].r_offset == address) {
      ret.address = rela_tbl[i].r_offset;
      ret.name = malloc(strlen(str_tbl + name_index) * sizeof(char));
      strcpy(ret.name, str_tbl + name_index);
      ret.size = dynsym_tbl[ELF64_R_SYM(rela_tbl[i].r_info)].st_size;
    }
  }
  free(rela_tbl);
  free(dynsym_tbl);
  free(str_tbl);
  return ret;
}