#include "key_paths.h"
#include "../keymgmt/key_store.h"
#include <string.h>

void exe_relative_path(const char *argv0, const char *filename, char *out, size_t out_size)
{
    const char *slash = strrchr(argv0, '/');
#ifdef _WIN32
    const char *backslash = strrchr(argv0, '\\');
    if (backslash != NULL && (slash == NULL || backslash > slash)) {
        slash = backslash;
    }
#endif

    if (slash != NULL) {
        size_t dir_len = (size_t) (slash - argv0) + 1;
        if (dir_len + strlen(filename) < out_size) {
            memcpy(out, argv0, dir_len);
            strcpy(out + dir_len, filename);
            return;
        }
    }
    strncpy(out, filename, out_size - 1);
    out[out_size - 1] = '\0';
}

int demo_load_keys(const char *argv0)
{
    char exe_relative[512];
    int loaded = key_store_load_file("keys.txt");
    if (loaded > 0) {
        return loaded;
    }

    if (argv0 != NULL) {
        exe_relative_path(argv0, "keys.txt", exe_relative, sizeof(exe_relative));
        loaded = key_store_load_file(exe_relative);
        if (loaded > 0) {
            return loaded;
        }
    }

    loaded = key_store_load_file("keymgmt/keys.txt");
    if (loaded > 0) {
        return loaded;
    }

    loaded = key_store_load_file("security/keymgmt/keys.txt");
    if (loaded > 0) {
        return loaded;
    }

    return key_store_load_file("../keymgmt/keys.txt");
}