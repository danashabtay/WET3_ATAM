#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    FILE *file = fopen(exe_file_name, "rb");
    if (file == NULL) {
        return -1;
    }

    Elf64_Ehdr elf_header;
    fread(&elf_header,sizeof(elf_header),1,file);
    Elf64_Half elf_type = elf_header.e_type;

    print("here");
    
    //check if the type is exe:
    if(elf_type!=2) {
        *error_val = -3;
        fclose(file);
        return -1;
    }

    //else, the ELF file is an exe file:
    // find section table offset from beginning of file:
    Elf64_Off section_offset=elf_header.e_shoff;
    // size of entry in section table:
    Elf64_Half section_size=elf_header.e_shentsize;
    //num of entries in section table:
    Elf64_Half section_num=elf_header.e_shnum;

    Elf64_Shdr section_header_table;
    fseek(file, section_offset, SEEK_SET);
    fread(&section_header_table,(section_num*section_size),1,file);

    //find SYMTAB inside section header table:
    while(section_header_table.sh_type!=0x2){
        fseek(file, section_size, SEEK_CUR);
        fread(&section_header_table,sizeof(Elf64_Shdr),1,file);
    }
    //file curr at section table->entry is symtab

    //offset of symtable from beginning of file:
    Elf64_Off symtable_offset = section_header_table.sh_offset;
    // entry size of symbol in symbol table:
    Elf64_Xword entry_size_symtable = section_header_table.sh_entsize;
    // symbol table size:
    Elf64_Xword sym_table_size = section_header_table.sh_size;
    // num of section in section header table that is the string table belonging to symtable - strtable:
    Elf64_Word sym_table_link = section_header_table.sh_link;

    Elf64_Xword num_symbols = sym_table_size/entry_size_symtable;

    //create sym_table:
    Elf64_Sym symbol_table;
    fseek(file,symtable_offset,SEEK_SET);
    fread(&symbol_table, sym_table_size, 1, file);


    //find STRTAB inside section header table:
    fseek(file,section_offset+(sym_table_link*section_size),SEEK_SET);
    fread(&section_header_table,sizeof(Elf64_Shdr),1,file);
    //file curr at section table->entry is strtab
    Elf64_Xword str_table_size = section_header_table.sh_size;
    // offset of strtab from beginning of file:
    Elf64_Off strtab_offset = section_header_table.sh_offset;
    //create str_table:
    char* str_table = (char*)malloc(str_table_size);
    fseek(file,strtab_offset,SEEK_SET);
    fread(str_table,str_table_size,1,file);


    //iterate over sym_table:
    int flag = 0;
    for (Elf64_Xword j = 0; j < num_symbols; j++) {
        fseek(file,symtable_offset+(j*entry_size_symtable),SEEK_SET);
        fread(&symbol_table,sym_table_size,1,file);
        char *curr_symbol_name = str_table + symbol_table.st_name;
        if (strcmp(curr_symbol_name, symbol_name) == 0) {
            if(ELF64_ST_BIND(symbol_table.st_info)==1){
                if(symbol_table.st_shndx==0){
                    *error_val = -4;
                    free(str_table);
                    fclose(file);
                    return -1;
                }
                else {
                    free(str_table);
                    fclose(file);
                    return symbol_table.st_value;
                }
            }
            if(ELF64_ST_BIND(symbol_table.st_info)==0){
                flag =1;
                continue;
            }
            break;
        }
    }
    //if symbol is found but is a local symbol:
    if(flag==1){
        *error_val = -2;
        free(str_table);
        fclose(file);
        return -1;
    }
    //if symbol is not found in sym_table:
    *error_val = -1;
    free(str_table);
    fclose(file);
    return -1;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}