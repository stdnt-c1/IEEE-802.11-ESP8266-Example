#ifndef SEQUENCE_HANDLER_H
#define SEQUENCE_HANDLER_H

#include <stdint.h>


// Atomic sequence number handler for ESP8266
static volatile uint16_t sequence_number = 0;

// Get next sequence number atomically (12-bit wraparound)
static inline uint16_t get_next_sequence_atomic() {
    uint16_t seq;
    noInterrupts();
    seq = sequence_number;
    sequence_number = (sequence_number + 1) & 0x0FFF;
    interrupts();
    return seq;
}

// Reset sequence number
static inline void reset_sequence() {
    noInterrupts();
    sequence_number = 0;
    interrupts();
}

#endif // SEQUENCE_HANDLER_H
