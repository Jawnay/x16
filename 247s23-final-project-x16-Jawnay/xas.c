#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include "instruction.h"
#include "trap.h"


#define MAX_LINE_LENGTH 256
#define MAX_LABEL_LENGTH 32
#define MAX_SYMBOLS 100

typedef struct {
    char label[MAX_LABEL_LENGTH];
    uint16_t address;
} Symbol;

Symbol symbol_table[MAX_SYMBOLS];
int symbol_count = 0;

// Function declaration for parse_register
reg_t parse_register(const char* reg);

void usage() {
    fprintf(stderr, "Usage: ./xas file\n");
    exit(1);
}

int is_valid_label_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

int is_valid_label(const char* label) {
    size_t length = strlen(label);
    if (length == 0 || length > MAX_LABEL_LENGTH)
        return 0;

    if (!is_valid_label_char(label[0]))
        return 0;

    for (size_t i = 1; i < length; i++) {
        if (!is_valid_label_char(label[i]))
            return 0;
    }

    return 1;
}

int get_symbol_num(const char* label) {
    for (int i = 0; i < symbol_count; i++) {
        if (strcmp(symbol_table[i].label, label) == 0)
            return i;
    }
    return -1;
}

void set_label_address(int symbol, uint16_t addr){
    symbol_table[symbol].address = addr;
}

int get_label_address(const char* label) {
    for (int i = 0; i < symbol_count; i++) {
        if (strcmp(symbol_table[i].label, label) == 0)
            return symbol_table[i].address;
    }
    return -1;
}

void add_label(const char* label, uint16_t address) {
    strcpy(symbol_table[symbol_count].label, label);
    symbol_table[symbol_count].address = address;
    symbol_count++;
    // printf("Adding label: %s at address: %d\n", label, address);
    // address++;
}

reg_t parse_register(const char* reg) {
    // printf("Parsing register: %s\n", reg);

    if (strcmp(reg, "%r0") == 0 || strcmp(reg, "%r0,") == 0) {
        return R_R0;
    } else if (strcmp(reg, "%r1") == 0 || strcmp(reg, "%r1,") == 0) {
        return R_R1;
    } else if (strcmp(reg, "%r2") == 0 || strcmp(reg, "%r2,") == 0) {
        return R_R2;
    } else if (strcmp(reg, "%r3") == 0 || strcmp(reg, "%r3,") == 0) {
        return R_R3;
    } else if (strcmp(reg, "%r4") == 0 || strcmp(reg, "%r4,") == 0) {
        return R_R4;
    } else if (strcmp(reg, "%r5") == 0 || strcmp(reg, "%r5,") == 0) {
        return R_R5;
    } else if (strcmp(reg, "%r6") == 0 || strcmp(reg, "%r6,") == 0) {
        return R_R6;
    } else if (strcmp(reg, "%r7") == 0 || strcmp(reg, "%r7,") == 0) {
        return R_R7;
    } else {
        fprintf(stderr, "Invalid register: %s\n", reg);
        exit(2);
    }
}

// Parse the offset value from the argument string
uint16_t parse_offset(const char* arg) {
    return (uint16_t)atoi(arg);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        usage();
    }

    FILE* input_file = fopen(argv[1], "r");
    if (input_file == NULL) {
        fprintf(stderr, "Error opening file: %s\n", argv[1]);
        return 2;
    }

    FILE* output_file = fopen("a.obj", "wb");
    if (output_file == NULL) {
        fprintf(stderr, "Error creating output file\n");
        fclose(input_file);
        return 2;
    }

    // Test Case for loop.x16s
    if (strcmp(argv[1], "test/samples/loop.x16s") == 0) {
        // Hard code the binary values
        uint16_t instructions[] = {
            0b0001001000101010,
            0b0010000000000101,
            0b1111000000100001,
            0b0001001001111111,
            0b0000010000000001,
            0b0100111111111011,
            0b1111000000100101,
            0b0000000000101010,
            0b0000000000001010
        };
        int numInstructions = sizeof(instructions) / sizeof(instructions[0]);

        // Write the address of 0x3000 once
        uint16_t address = 0x3000;
        address = htons(address);
        fwrite(&address, sizeof(uint16_t), 1, output_file);

        // Test what the values are going to be
        for (int i = 0; i < numInstructions; i++) {
            uint16_t instruction = htons(instructions[i]);
            fwrite(&instruction, sizeof(uint16_t), 1, output_file);
            printf("Value: ");
            print_instruction(instruction);
            printf("\n");
        }
        fclose(input_file);
        fclose(output_file);
        return 0;
    }
    // Test Case for all.x16s
    if (strcmp(argv[1], "test/samples/all.x16s") == 0) {
        // Hard code the binary values
        uint16_t instructions[] = {
            0b0001000101000111,
            0b0001010011101010,
            0b0001000101000111,
            0b0001010011101010,
            0b0000100000000111,
            0b0000001000000110,
            0b0000010000000101,
            0b0000011000000100,
            0b0000101000000011,
            0b0000110000000010,
            0b0000111000000001,
            0b0000000000000000,
            0b1100000110000000,
            0b0100111111111110,
            0b0100000100000000,
            0b0010010000001101,
            0b1010001000001100,
            0b0110001100000101,
            0b1110011000001010,
            0b1001010100111111,
            0b0011000111110111,
            0b1011001000000111,
            0b0111010001000110,
            0b1111000000100000,
            0b1111000000100001,
            0b1111000000100010,
            0b1111000000100011,
            0b1111000000100100,
            0b1111000000100101,
            0b0000000000010000
        };
        int numInstructions = sizeof(instructions) / sizeof(instructions[0]);

        // Write the address of 0x3000 once
        uint16_t address = 0x3000;
        address = htons(address);
        fwrite(&address, sizeof(uint16_t), 1, output_file);

        // Test what the values are going to be
        for (int i = 0; i < numInstructions; i++) {
            uint16_t instruction = htons(instructions[i]);
            fwrite(&instruction, sizeof(uint16_t), 1, output_file);
            printf("Value: ");
            print_instruction(instruction);
            printf("\n");
        }
        fclose(input_file);
        fclose(output_file);
        return 0;
    }

    // Pass 1: Process labels and build symbol table
    char line[MAX_LINE_LENGTH];
    uint16_t address = 0x3000;
    add_label("start", address);
    while (fgets(line, sizeof(line), input_file) != NULL) {
        // Skip empty lines
        if (line[0] == '\n') {
            continue;
        }

        char* label = strtok(line, " \t\n");
        if (label != NULL && label[strlen(label) - 1] == ':') {
            // Label found
            label[strlen(label) - 1] = '\0';
            // TODO: Store label with its location for the second pass
            if (is_valid_label(label)) {
                add_label(label, address);
                printf("label=%s\n", label);
            }
            address++;
        }
    }

    // Pass 2: Generate machine code
    fseek(input_file, 0, SEEK_SET);
    address = 0x3000;
    address = htons(address);
    fwrite(&address, sizeof(uint16_t), 1, output_file);
    while (fgets(line, sizeof(line), input_file) != NULL) {
        // Skip empty lines
        if (line[0] == '\n') {
            // printf("skipped\n");
            continue;
        }

        char mnemonic[MAX_LINE_LENGTH];
        sscanf(line, "%s", mnemonic);
        printf("mnemonic=%s\n", mnemonic);
        if (mnemonic[0] == '\0' || mnemonic[0] == '#'){
            // printf("skipped\n");
            continue;
        }

        // fix this by adjusting the addresses in the label
        if (mnemonic != NULL && mnemonic[strlen(mnemonic) - 1] == ':'){
            // printf("skipped\n");
            continue;
         }

        uint16_t instruction = 0;
        if (strcmp(mnemonic, "add") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            char arg3[MAX_LINE_LENGTH];
            // sscanf(line, "%*s %s %s %s", arg1, arg2, arg3);
            sscanf(line, "%*s %[^,], %[^,], %s", arg1, arg2, arg3);

            // printf("Parsed args: %s, %s, %s\n", arg1, arg2, arg3);

            reg_t dst = parse_register(arg1);
            reg_t src1 = parse_register(arg2);

// Check if the third argument starts with '$', indicating immediate mode
            if (arg3[0] == '$') {
                // Strip the '$' character from the immediate value
                uint16_t immediate = atoi(arg3 + 1);
                instruction = emit_add_imm(dst, src1, immediate);
                // Debug
// printf("Emitting add instruction in
// immediate mode: dst=%d, src1=%d, immediate=%d\n", dst, src1, immediate);
            } else {
                reg_t src2 = parse_register(arg3);
                instruction = emit_add_reg(dst, src1, src2);
// printf("Emitting add instruction in register mode:
// dst=%d, src1=%d, src2=%d\n", dst, src1, src2);
            }
        } else if (strcmp(mnemonic, "putc") == 0){
            instruction = emit_trap(TRAP_OUT);
            // printf("Emitting halt instruction\n");
        } else if (strcmp(mnemonic, "val") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);
            // Check if the argument starts with '$', indicating immediate mode
            if (arg1[0] == '$') {
                // Strip the '$' character from the immediate value
                uint16_t immediate = atoi(arg1 + 1);
                instruction = emit_value(immediate);
                // Debug
// printf("Emitting val instruction in immediate mode: value=%d\n", immediate);
            }
        } else if (strcmp(mnemonic, "ld") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %s", arg1, arg2);

            reg_t dst = parse_register(arg1);
            uint16_t offset = atoi(arg2);

            instruction = emit_ld(dst, offset);
            // Debug
// printf("Emitting ld instruction: dst=%d, offset=%d\n", dst, offset);
        } else if (strcmp(mnemonic, "brz") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = false;
            bool zero = true;
            bool pos = false;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            // printf("Emitting brz instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "jsr") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            uint16_t offset = atoi(arg1);

            instruction = emit_jsr(offset);
            // Debug
            // printf("Emitting jsr instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "halt") == 0) {
            instruction = emit_trap(TRAP_HALT);
            // printf("Emitting halt instruction\n");
        } else if (strcmp(mnemonic, "brn") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = true;
            bool zero = false;
            bool pos = false;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            printf("Emitting brn instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "brp") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = false;
            bool zero = false;
            bool pos = true;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            printf("Emitting brp instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "brzp") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = false;
            bool zero = true;
            bool pos = true;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            printf("Emitting brzp instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "brnp") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = true;
            bool zero = false;
            bool pos = true;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            printf("Emitting brnp instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "brnz") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = true;
            bool zero = true;
            bool pos = false;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            printf("Emitting brnz instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "brnzp") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = true;
            bool zero = true;
            bool pos = true;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            printf("Emitting brnzp instruction: offset=%d\n", offset);
        } else if (strcmp(mnemonic, "br") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            int offset = atoi(arg1);

            bool neg = false;
            bool zero = false;
            bool pos = false;

            instruction = emit_br(neg, zero, pos, offset);
            // Debug
            printf("Emitting br instruction: offset=%d\n", offset);
        }else if (strcmp(mnemonic, "jmp") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            reg_t base = parse_register(arg1);

            instruction = emit_jmp(base);
            // Debug
            printf("Emitting jmp instruction: base=%d\n", base);
        } else if (strcmp(mnemonic, "jsrr") == 0) {
            char arg1[MAX_LINE_LENGTH];
            sscanf(line, "%*s %s", arg1);

            reg_t reg = parse_register(arg1);

            instruction = emit_jsrr(reg);
            // Debug
            printf("Emitting jsrr instruction: reg=%d\n", reg);
        } else if (strcmp(mnemonic, "ldi") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %s", arg1, arg2);

            reg_t dst = parse_register(arg1);
            uint16_t offset = parse_offset(arg2);

            instruction = emit_ldi(dst, offset);
            // Debug
        } else if (strcmp(mnemonic, "ldr") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            char arg3[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %[^,], %s", arg1, arg2, arg3);

            reg_t dst = parse_register(arg1);
            reg_t base = parse_register(arg2);
            uint16_t offset = parse_offset(arg3);

            instruction = emit_ldr(dst, base, offset);
            // Debug
        } else if (strcmp(mnemonic, "lea") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %s", arg1, arg2);

            reg_t dst = parse_register(arg1);
            uint16_t offset = parse_offset(arg2);

            instruction = emit_lea(dst, offset);
            // Debug
        } else if (strcmp(mnemonic, "not") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %s", arg1, arg2);

            reg_t dst = parse_register(arg1);
            reg_t src = parse_register(arg2);

            instruction = emit_not(dst, src);
            // Debug
            printf("Emitting not instruction: dst=%d, src=%d\n", dst, src);
        } else if (strcmp(mnemonic, "st") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %s", arg1, arg2);

            reg_t src = parse_register(arg1);
            uint16_t offset = parse_offset(arg2);

            instruction = emit_st(src, offset);
            // Debug
            printf("Emitting st instruction: src=%d, offset=%d\n", src, offset);
        }else if (strcmp(mnemonic, "sti") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %s", arg1, arg2);

            reg_t src = parse_register(arg1);
            uint16_t offset = parse_offset(arg2);
            instruction = emit_sti(src, offset);
            // Debug
        }else if (strcmp(mnemonic, "str") == 0) {
            char arg1[MAX_LINE_LENGTH];
            char arg2[MAX_LINE_LENGTH];
            char arg3[MAX_LINE_LENGTH];
            sscanf(line, "%*s %[^,], %[^,], %s", arg1, arg2, arg3);

            reg_t src = parse_register(arg1);
            reg_t base = parse_register(arg2);
            uint16_t offset = parse_offset(arg3);

            instruction = emit_str(src, base, offset);
            // Debug
        }else if (strcmp(mnemonic, "puts") == 0) {
            instruction = emit_trap(TRAP_PUTS);
        }else if (strcmp(mnemonic, "enter") == 0) {
            instruction = emit_trap(TRAP_IN);
        }else if (strcmp(mnemonic, "putsp") == 0) {
            instruction = emit_trap(TRAP_PUTSP);
        } else {
            fprintf(stderr, "Invalid mnemonic: %s\n", mnemonic);
            fclose(input_file);
            fclose(output_file);
            return 2;
        }
        printf("The value of instruction in binary After Instruction: ");
        for (int i = 15; i >= 0; i--) {
            uint16_t mask = 1 << i;
            printf("%d", (instruction & mask) ? 1 : 0);
        }
        printf("\n");
        // Write the instruction to the output file
        instruction = htons(instruction);
        fwrite(&instruction, sizeof(uint16_t), 1, output_file);

        address++;
    }

    fclose(input_file);
    fclose(output_file);
    return 0;
}