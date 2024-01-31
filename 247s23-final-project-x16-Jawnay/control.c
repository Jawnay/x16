#include <stdio.h>
#include <stdlib.h>
#include "bits.h"
#include "control.h"
#include "instruction.h"
#include "x16.h"
#include "trap.h"


// Update condition code based on result
void update_cond(x16_t* machine, reg_t reg) {
    uint16_t result = x16_reg(machine, reg);
    if (result == 0) {
        x16_set(machine, R_COND, FL_ZRO);
    } else if (is_negative(result)) {
        x16_set(machine, R_COND, FL_NEG);
    } else {
        x16_set(machine, R_COND, FL_POS);
    }
}

// Execute a single instruction in the given X16 machine. Update
// memory and registers as required. PC is advanced as appropriate.
// Return 0 on success, or -1 if an error or HALT is encountered.
int execute_instruction(x16_t* machine) {
    // Fetch the instruction and advance the program counter
    uint16_t pc = x16_pc(machine);
    uint16_t instruction = x16_memread(machine, pc);
    x16_set(machine, R_PC, pc + 1);
    reg_t reg;
    // Decode the instruction and execute it
    uint16_t opcode = getopcode(instruction);
    reg_t dr;
    reg_t sr1;
    reg_t sr2;
    uint16_t ext;
    uint16_t contents;
    switch (opcode) {
        case OP_ADD:
            int value;
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            if (getbit(instruction, 5) == 0){
                // add the two source register values together
                
                value = x16_reg(machine, x16_getReg
                (machine, getbits(instruction, 0, 3))) +
                x16_reg(machine, x16_getReg
                (machine, getbits(instruction, 6, 3)));
                // set the DR to the value
                x16_set(machine, dr, value);
            } else {
                uint16_t extend = sign_extend(instruction, 5);
                value = extend + x16_reg(machine, x16_getReg
                (machine, getbits(instruction, 6, 3)));
                x16_set(machine, dr, value);
            }
            update_cond(machine, dr);
            break;

        case OP_AND:
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            sr1 = x16_getReg(machine, getbits(instruction, 6, 3));
            if (getbit(instruction, 5) == 0){
                sr2 = x16_getReg(machine, getbits(instruction, 0, 3));
                uint16_t anded = x16_reg(machine, sr1) & x16_reg(machine, sr2);
                x16_set(machine, dr, anded);
            } else {
                uint16_t extend = sign_extend(instruction, 5);
                uint16_t anded = x16_reg(machine, sr1) & extend;
                x16_set(machine, dr, anded);
            }
            update_cond(machine, dr);
            break;

        case OP_NOT:
            sr1 = x16_getReg(machine, getbits(instruction, 6, 3));
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            uint16_t comp = ~x16_reg(machine, sr1);
            x16_set(machine, dr, comp);
            update_cond(machine, dr);
            break;

        case OP_BR:
            condition_t flag = x16_reg(machine, R_COND);
            int n = getbit(instruction, 11);
            int z = getbit(instruction, 10);
            int p = getbit(instruction, 9);
            if (n == 1 && flag == FL_NEG || z == 1 &&
            flag == FL_ZRO || p == 1 && flag == FL_POS){
                uint16_t extend = sign_extend(instruction, 9);
                x16_set(machine, R_PC, pc + extend + 1);
            }
            break;

        case OP_JMP:
            sr1 = x16_getReg(machine, getbits(instruction, 6, 3));
            contents = x16_reg(machine, sr1);
            x16_set(machine, R_PC, contents);
            break;

        case OP_JSR:
            x16_set(machine, R_R7, pc+1);
            if (getbit(instruction, 11) == 0){
                sr1 = x16_getReg(machine, getbits(instruction, 6, 3));
                contents = x16_reg(machine, sr1);
                x16_set(machine, R_PC, contents);
            } else {
                uint16_t extend = sign_extend(instruction, 11);
                pc++;
                x16_set(machine, R_PC, extend + pc);
            }
            break;

        case OP_LD:
            uint16_t extend = sign_extend(instruction, 9);
            pc++;
            int addr = pc + extend;
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            uint16_t mem = x16_memread(machine, addr);
            x16_set(machine, dr, mem);
            update_cond(machine, dr);
            break;

        case OP_LDI:
            ext = sign_extend(instruction, 9);
            pc++;
            addr = ext + pc;
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            uint16_t data = x16_memread(machine, x16_memread(machine, addr));
            x16_set(machine, dr, data);
            update_cond(machine, dr);
            break;

        case OP_LDR:
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            ext = sign_extend(instruction, 6);
            sr1 = x16_getReg(machine, getbits(instruction, 6, 3));
            addr = x16_reg(machine, sr1) + ext;
            mem = x16_memread(machine, addr);
            x16_set(machine, dr, mem);
            update_cond(machine, dr);
            break;

        case OP_LEA:
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            ext = sign_extend(instruction, 9);
            pc++;
            addr = ext + pc;
            x16_set(machine, dr, addr);
            update_cond(machine, dr);
            break;

        case OP_ST:
            sr1 = x16_getReg(machine, getbits(instruction, 9, 3));
            contents = x16_reg(machine, sr1);
            ext = sign_extend(instruction, 9);
            pc++;
            addr = ext + pc;
            x16_memwrite(machine, addr, contents);
            break;

        case OP_STI:
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            ext = sign_extend(instruction, 9);
            pc++;
            addr = ext + pc;
            contents = x16_reg(machine, dr);
            x16_memwrite(machine, x16_memread(machine, addr), contents);
            break;

        case OP_STR:
            dr = x16_getReg(machine, getbits(instruction, 9, 3));
            uint16_t offset = sign_extend(instruction, 6);
            sr1 = x16_getReg(machine, getbits(instruction, 6, 3));
            addr = x16_reg(machine, sr1) + offset;
            contents = x16_reg(machine, dr);
            x16_memwrite(machine, addr, contents);
            break;


        case OP_TRAP:
            // Execute the trap
            return trap(machine, instruction);

        case OP_RES:
        case OP_RTI:
        default:
            // Bad codes, never used
            abort();
    }

    return 0;
}

