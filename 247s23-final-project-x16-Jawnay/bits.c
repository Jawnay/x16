#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include "bits.h"


#define assert_bit(a) if ((a) != 0 && (a) != 1) { assert(false); }

uint16_t getbit(uint16_t number, int n) {
    // Validate that n is within the valid range
    assert(n >= 0 && n < 16);
    return (number >> n) & 1;
}

// Get bits that are the given number of bits wide
uint16_t getbits(uint16_t number, int n, int wide) {
    // Ensure n and wide are within valid range
    assert(n >= 0 && n < 16 && wide > 0 && wide <= 16);
    return (number >> n) & ((1 << wide) - 1);
}

// Set the nth bit to the given bit value and return the result
uint16_t setbit(uint16_t number, int n) {
    // Ensure n is within valid range
    assert(n >= 0 && n < 16);
    return number | (1 << n);
}

// Clear the nth bit
uint16_t clearbit(uint16_t number, int n) {
    // Ensure n is within valid range
    assert(n >= 0 && n < 16);
    return number & ~(1 << n);
}

// Sign extend a number of the given bits to 16 bits
uint16_t sign_extend(uint16_t x, int bit_count) {
    int bit = getbit(x, bit_count - 1);
    if (bit == 1){
        for (int i = bit_count; i < 16; i++){
            x = setbit(x, i);
        }
    } else if (bit == 0){
        for (int i = bit_count; i < 16; i++){
            x = clearbit(x, i);
        }
    }
    return x;
}

bool is_positive(uint16_t number) {
    return getbit(number, 15) == 0;
}


bool is_negative(uint16_t number) {
    return getbit(number, 15) == 1;
}


