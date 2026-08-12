#include "key_store.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KEY_STORE_MAX_ADDR 247 /* Modbus slave address 최댓값 */
#define KEY_STORE_NUM_DIRS  3  /* DIR_MASTER_TO_SLAVE, DIR_SLAVE_TO_MASTER, DIR_BROADCAST */

typedef struct {
    int valid;
    directional_keys_t keys;
    uint32_t initial_ctr;
} key_entry_t;

static key_entry_t table[KEY_STORE_MAX_ADDR + 1][KEY_STORE_NUM_DIRS];

static int dir_index(key_direction_t dir, int *out)
{
    if (dir != DIR_MASTER_TO_SLAVE && dir != DIR_SLAVE_TO_MASTER && dir != DIR_BROADCAST) {
        return -1;
    }
    *out = (int) dir;
    return 0;
}

static int parse_dir(const char *tok, key_direction_t *out)
{
    if (strcmp(tok, "m2s") == 0) {
        *out = DIR_MASTER_TO_SLAVE;
    } else if (strcmp(tok, "s2m") == 0) {
        *out = DIR_SLAVE_TO_MASTER;
    } else if (strcmp(tok, "bc") == 0) {
        *out = DIR_BROADCAST;
    } else {
        return -1;
    }
    return 0;
}

int key_store_lookup(uint8_t slave_addr, key_direction_t dir, directional_keys_t *out)
{
    int di;

    if (slave_addr > KEY_STORE_MAX_ADDR || dir_index(dir, &di) != 0) {
        return -1;
    }
    if (!table[slave_addr][di].valid) {
        return -1;
    }

    *out = table[slave_addr][di].keys;
    return 0;
}

int key_store_provision(uint8_t slave_addr, key_direction_t dir, const directional_keys_t *keys)
{
    int di;

    if (slave_addr > KEY_STORE_MAX_ADDR || dir_index(dir, &di) != 0) {
        return -1;
    }

    table[slave_addr][di].keys = *keys;
    table[slave_addr][di].initial_ctr = 0;
    table[slave_addr][di].valid = 1;
    return 0;
}

int key_store_get_initial_ctr(uint8_t slave_addr, key_direction_t dir, uint32_t *out)
{
    int di;

    if (slave_addr > KEY_STORE_MAX_ADDR || dir_index(dir, &di) != 0) {
        return -1;
    }
    if (!table[slave_addr][di].valid) {
        return -1;
    }

    *out = table[slave_addr][di].initial_ctr;
    return 0;
}

int key_store_load_file(const char *path)
{
    FILE *f;
    char line[256];
    int loaded = 0;

    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned int addr;
        char dir_tok[8];
        char enc_tok[24];
        char mac_tok[24];
        char ctr_tok[16];
        char *p = line;
        key_direction_t dir;
        directional_keys_t keys;
        int di;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') {
            continue;
        }

        if (sscanf(p,
                   "%u %7s %23s %23s %15s",
                   &addr,
                   dir_tok,
                   enc_tok,
                   mac_tok,
                   ctr_tok) != 5) {
            continue;
        }
        if (addr > KEY_STORE_MAX_ADDR || strlen(enc_tok) != KEY_SIZE ||
            strlen(mac_tok) != KEY_SIZE || parse_dir(dir_tok, &dir) != 0 ||
            dir_index(dir, &di) != 0) {
            continue;
        }

        memcpy(keys.enc_key, enc_tok, KEY_SIZE);
        memcpy(keys.mac_key, mac_tok, KEY_SIZE);

        table[addr][di].keys = keys;
        table[addr][di].initial_ctr = (uint32_t) strtoul(ctr_tok, NULL, 16);
        table[addr][di].valid = 1;
        loaded++;
    }

    fclose(f);
    return loaded;
}