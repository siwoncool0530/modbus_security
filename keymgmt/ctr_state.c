#include "ctr_state.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define CTR_STATE_MAX_ADDR 247
#define CTR_STATE_NUM_DIRS  3
#define CTR_STATE_DEFAULT_PATH "ctr_state.dat"

typedef struct {
    int valid_out;
    uint32_t next_out;
    int valid_in;
    uint32_t high_in;
} ctr_entry_t;

static ctr_entry_t table[CTR_STATE_MAX_ADDR + 1][CTR_STATE_NUM_DIRS];
static char state_path[512] = CTR_STATE_DEFAULT_PATH;

static const char *dir_name(key_direction_t dir)
{
    switch (dir) {
    case DIR_MASTER_TO_SLAVE:
        return "m2s";
    case DIR_SLAVE_TO_MASTER:
        return "s2m";
    default:
        return "bc";
    }
}

void ctr_state_set_path(const char *path)
{
    strncpy(state_path, path, sizeof(state_path) - 1);
    state_path[sizeof(state_path) - 1] = '\0';
}

void ctr_state_reset(uint8_t slave_addr, key_direction_t dir)
{
    int di;

    if (slave_addr > CTR_STATE_MAX_ADDR || key_direction_index(dir, &di) != 0) {
        return;
    }
    table[slave_addr][di].valid_out = 0;
    table[slave_addr][di].valid_in = 0;
    ctr_state_persist();
}

uint32_t ctr_state_next_outgoing(uint8_t slave_addr, key_direction_t dir, size_t msg_len)
{
    int di;
    uint32_t value;
    uint32_t seed;
    uint32_t num_blocks;

    if (slave_addr > CTR_STATE_MAX_ADDR || key_direction_index(dir, &di) != 0) {
        return 0;
    }

    if (!table[slave_addr][di].valid_out) {
        seed = 0;
        key_store_get_initial_ctr(slave_addr, dir, &seed);
        table[slave_addr][di].next_out = seed;
        table[slave_addr][di].valid_out = 1;
    }

    /* LEA-CTR은 16바이트 블록마다 카운터를 1씩 증가시키므로, 이번 메시지가 소비할
       블록 수만큼 예약해야 다음 메시지의 시작 카운터가 이번 메시지의 뒤쪽 블록과
       겹치지 않음 (1바이트라도 있으면 최소 한 블록은 소비하므로 msg_len==0도 1로 처리). */
    num_blocks = (uint32_t) ((msg_len + 15) / 16);
    if (num_blocks == 0) {
        num_blocks = 1;
    }

    value = table[slave_addr][di].next_out;
    table[slave_addr][di].next_out = value + num_blocks;
    ctr_state_persist();
    return value;
}

int ctr_state_validate_incoming(uint8_t slave_addr, key_direction_t dir, uint32_t ctr)
{
    int di;
    uint32_t seed;

    if (slave_addr > CTR_STATE_MAX_ADDR || key_direction_index(dir, &di) != 0) {
        return 0;
    }

    if (!table[slave_addr][di].valid_in) {
        seed = 0;
        key_store_get_initial_ctr(slave_addr, dir, &seed);
        if (ctr < seed) {
            return 0;
        }
        table[slave_addr][di].high_in = ctr;
        table[slave_addr][di].valid_in = 1;
        ctr_state_persist();
        return 1;
    }

    if (ctr < table[slave_addr][di].high_in) {
        return 0; /* replay */
    }
    if (ctr == table[slave_addr][di].high_in) {
        return 1; /* legitimate retry */
    }

    table[slave_addr][di].high_in = ctr;
    ctr_state_persist();
    return 1;
}

int ctr_state_persist(void)
{
    FILE *f;
    uint8_t addr;
    int di;

    f = fopen(state_path, "w");
    if (f == NULL) {
        return -1;
    }

    for (addr = 0; addr <= CTR_STATE_MAX_ADDR; addr++) {
        for (di = 0; di < CTR_STATE_NUM_DIRS; di++) {
            ctr_entry_t *e = &table[addr][di];
            if (!e->valid_out && !e->valid_in) {
                continue;
            }
            fprintf(f,
                    "%u %s %d %u %d %u\n",
                    (unsigned int) addr,
                    dir_name((key_direction_t) di),
                    e->valid_out,
                    (unsigned int) e->next_out,
                    e->valid_in,
                    (unsigned int) e->high_in);
        }
        if (addr == CTR_STATE_MAX_ADDR) {
            break; /* uint8_t wraps before the loop condition can stop it */
        }
    }

    fclose(f);
    return 0;
}

int ctr_state_load(void)
{
    FILE *f;
    char line[256];

    f = fopen(state_path, "r");
    if (f == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned int addr, next_out, high_in;
        int valid_out, valid_in;
        char dir_tok[8];
        key_direction_t dir;
        int di;

        if (sscanf(line,
                   "%u %7s %d %u %d %u",
                   &addr,
                   dir_tok,
                   &valid_out,
                   &next_out,
                   &valid_in,
                   &high_in) != 6) {
            continue;
        }
        if (addr > CTR_STATE_MAX_ADDR) {
            continue;
        }
        if (strcmp(dir_tok, "m2s") == 0) {
            dir = DIR_MASTER_TO_SLAVE;
        } else if (strcmp(dir_tok, "s2m") == 0) {
            dir = DIR_SLAVE_TO_MASTER;
        } else if (strcmp(dir_tok, "bc") == 0) {
            dir = DIR_BROADCAST;
        } else {
            continue;
        }
        if (key_direction_index(dir, &di) != 0) {
            continue;
        }

        table[addr][di].valid_out = valid_out;
        table[addr][di].next_out = next_out;
        table[addr][di].valid_in = valid_in;
        table[addr][di].high_in = high_in;
    }

    fclose(f);
    return 0;
}