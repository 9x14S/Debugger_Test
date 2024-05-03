#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "debugger.h"

#define DEBUG 1

enum errors 
{
  SUCCESS, 
  BAD_USAGE, 
  NOT_IMPLEMENTED,
  CAPSTONE_INITERR, 
  CAPSTONE_DISASSERR, 
  FORK_FAIL,
  OPEN_FAIL,
  NOT_ELF,
  BAD_ELF_BITS,
  EMPTY_FILE,
  MALLOC_BAILED,
};

// Set to true only for the child process 
bool is_child = false;

// POSIX provided environment pointer
extern char** environ;

// Global buffer for the instructions.
byte instructions[0x4000];



// Print error message and exit. Handles child exit separately from parent
void
printerr(char* str, int retval)
{
  fputs(str, stderr);

  // _Exit doesn't delete temporary files nor execute exit handlers
  if (is_child)
    _Exit(retval);
  else
    exit(retval);
}


void
usage(char* progname)
{
  fprintf(stderr, "usage: %s <binary> [args]\n", progname);
  exit(BAD_USAGE);
}


// Open, check and then return the file pointer.
FILE * 
open_file(char *filepath)
{

  FILE* file = fopen(filepath, "rb");
  if (NULL == file)
    printerr("Failed to open target file.\n", OPEN_FAIL);

  // Check file sizes and the like
  struct stat file_data;
  fstat(file->_fileno, &file_data);
  if (file_data.st_size == 0)
    printerr("Provided file is empty.", EMPTY_FILE);

#ifdef DEBUG
  printf("Size of file: %lu\n", file_data.st_size);
#endif 

  return file;
}


// Shit ELF parser. Returns a pointer to a malloc chunk filled with the 
// parsed data
void *
read_elf(FILE* file)
{
  void* elf_hdr = malloc(sizeof(struct elf_hdr64)); 
  if (NULL == elf_hdr)
    printerr("Couldn't allocate buffer for ELF header.", MALLOC_BAILED);

  fread(elf_hdr, 1, 64, file); // For 32-bit: reads a little bit more to keep this a single operation
  // Check if file is an ELF binary
  if (memcmp(elf_hdr, "\x7f""ELF", 4) != 0)
    printerr("Not an ELF file.\n", NOT_ELF);

  rewind(file);
  return elf_hdr;
}


// void
// run32(struct elf_hdr32* elf_hdr, FILE* f)
// {
//
// }


void
run64(struct elf_hdr64* elf_hdr, FILE* f)
{
  struct section_hdr64 shstrtab;

  // Get the address of the .shstrtab section.
  size_t addr = elf_hdr->sheader_offset + (elf_hdr->shstrndx * elf_hdr->shentsize);

#ifdef DEBUG
  printf("shstrtab header address: %lx\n", addr);
#endif

  fseek(f, addr, SEEK_SET);
  fread(&shstrtab, elf_hdr->shentsize, 1, f);


#ifdef DEBUG
  printf("shstrtab address: %lx\n", shstrtab.file_offset);
#endif


  struct section_hdr64 dot_text;

  /* Assume max str size = 22 */
  size_t shstrtab_size = elf_hdr->shnum * 22;
  char* str_buffer = (char *) malloc(shstrtab_size);

  fseek(f, shstrtab.file_offset, SEEK_SET);
  fread(str_buffer, shstrtab_size, 1, f);

  fseek(f, elf_hdr->sheader_offset, SEEK_SET);

  int i;
  for (i = 0; i < elf_hdr->shnum - 1 /* Minus .shstrtab */; i++)
  {
    fread(&dot_text, 64, 1, f);
    if (0 == strncmp(&(str_buffer[dot_text.str_index]), ".text", 5))
    {
      printf("Found .text section string index: %x\n", dot_text.str_index);
      puts("That means that this chunk is the .text section header.");
      break;
    }

  }

  // Read in all of the .text section
  fseek(f, dot_text.file_offset, SEEK_SET);
  size_t amount_read = fread(instructions, 1, dot_text.size, f);

  /* Disassemble */

  csh handle;
  cs_insn* insn;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    printerr("Failed to initialize capstone.\n", CAPSTONE_INITERR);



  size_t count = cs_disasm(handle, (uint8_t*)instructions, amount_read, elf_hdr->entry, 0, &insn);

  if (count > 0)
  {
    for (size_t i = 0; i < count; i++)
    {
      printf("%lx: %s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
    }
    cs_free(insn, count);

  }
  else
    printerr("Failed to disassemble given code.\n", CAPSTONE_DISASSERR);

  cs_close(&handle);



}


int
main(const int argc,  char* const argv[])
{
  if (argc < 2)
    usage(argv[0]);

  FILE* f = open_file(argv[1]);
  char* elf_hdr = read_elf(f);


  // Check the `elf_bits` member of the struct.
  if (elf_hdr[4] == 1) // 32-bit
  {
    free(elf_hdr);
    printerr("Not implemented yet.\n", NOT_IMPLEMENTED);
    // run32((struct elf_hdr32*)elf_hdr, f);
  }
  else if (elf_hdr[4] == 2) // 64-bit
  {
    run64((struct elf_hdr64*)elf_hdr, f);
  }
  else
  {
    free(elf_hdr);
    printerr("ELF format error: unrecognized word size for architecture (only 32-bits or 64-bits supported).", BAD_ELF_BITS);
  }

  // Assume the called functions have freed the chunk
  elf_hdr = NULL;


#ifndef DEBUG 

  pid_t child_pid = fork();
  if (child_pid == 0)
  {
    is_child = true; // Might be redundant
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvpe(argv[1], &(argv[1]), environ);
  }
  else if (child_pid == -1)
    printerr("Fork failed.\n", FORK_FAIL);

  int status;

  waitpid(child_pid, &status, 0);
  ptrace(PTRACE_CONT, child_pid, NULL, NULL);




  // START - DEBUG
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

  printf("RAX: %llx - RIP: %llx\n", regs.rax, regs.rip);
  // END - DEBUG


#endif 
  fclose(f);
  return 0;
}
