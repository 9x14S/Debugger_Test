#ifndef DEBUGGER_H
#define DEBUGGER_H 1
#include <stdio.h>
#include <stdint.h>

typedef uint8_t  byte;
typedef uint16_t word;
typedef uint32_t dword;
typedef uint64_t qword;


struct elf_hdr;


// Not meant to hold ALL data, only RELEVANT data (irrelevant data marked as _padding).
// Also, might not use the exact names of the specification
struct  elf_hdr32
{
  byte magic[4];
  byte elf_bits; // 1 if 32-bits, 2 if 64-bit

  byte _irrelevant1[10]; 

  word e_type; // Should always be 2 for executable
  word arch; // Either 3 for x86 or 62 (0x3e) for x64
  dword _irrelevant2;
  dword entry; // Entrypoint
  dword pheader_offset;
  dword sheader_offset;

  byte _irrelevant3[6];

  word phentsize; // Program header size
  word phnum; // Num of program headers
  word shentsize; // Section header size
  word shnum; // Num of section headers
  word shstrndx; 

  dword _irrelevant[3];
};


struct elf_hdr64
{
  byte magic[4];
  byte elf_bits; // 1 if 32-bits, 2 if 64-bit
  byte _irrelevant1[11]; 
  // 0x10


  word e_type; // Should always be 2 for executable
  word arch; // Either 3 for x86 or 62 (0x3e) for x64
  dword _irrelevant2;
  qword entry; // Entrypoint
  qword pheader_offset;
  qword sheader_offset;

  byte _irrelevant3[6];

  word phentsize; // Program header size
  word phnum; // Num of program headers
  word shentsize; // Section header size
  word shnum; // Num of section headers
  word shstrndx; 
};


struct section_hdr32
{
  dword str_index;
  byte _irrelevant1[12];
  dword file_offset;
  dword size;
  byte _irrelevant2[16];
};


struct section_hdr64
{
  dword str_index;
  byte _irrelevant1[20];
  qword file_offset;
  qword size;
  byte _irrelevant2[24];
};


void __attribute__((noreturn)) printerr(char *, int);
void __attribute__((noreturn)) usage(char *);
FILE* open_file(char *);
void run32(struct elf_hdr32*, FILE *);
void run64(struct elf_hdr64*, FILE *);

#endif /* DEBUGGER_H */
