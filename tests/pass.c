// #define EMU_BENCH
#include <anemu.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define MAX_LEN 64

#define TAINT_PASSWORD 0x00010000

void hide(char *password) {
    char stash[MAX_LEN];
    int c = 0;
    while(password[c] != '\0') {
        // obfuscate/hash password
        stash[c] = password[c] - 32;
        c++;
    }
    // write stashed password to disk or network socket
    int fd = open("/data/cache.tmp", O_CREAT | O_RDWR);
    write(fd, stash, c);
    close(fd);
}

bool login(char *password) {
    return true;
}

bool native_authenticate(char *password) {
    hide(password);
    return login(password);
}

// call args: <emu on/off> <runs>
int main(int argc, char ** argv) {
    if (argc != 3) return -1;
    int emu = atoi(argv[1]);
    int runs = atoi(argv[2]);
    int i;

    char *pass = "t0psecr3t!@#";

    char *buf = mmap(NULL, PAGE_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    
    printf("pass: %p buf: %p\n", pass, buf);

    memcpy(buf, pass, strlen(pass));

    struct timespec start, end;

    if (emu) {
        emu_set_target(getpid());
        emu_set_protect(false);
        emu_hook_thread_entry((void *)pthread_self());
        emu_set_taint_array((uintptr_t)buf, TAINT_PASSWORD, strlen(pass));
        emu_mprotect_mem(true);
        emu_reset_stats();
        time_ns(&start);
        EMU_MARKER_START;
    } else {
        time_ns(&start);
    }

    for (i = 0; i < runs; i++) {
        native_authenticate(buf);
    }

    if (emu) {
        EMU_MARKER_STOP;
        time_ns(&end);
        emu_unprotect_mem();
        emu_dump_stats();
        /* emu_dump_taintmaps(); */
        emu_dump_taintpages();
    } else {
        time_ns(&end);
    }

    printf("cycles = %lld\n", ns_to_cycles(diff_ns(&start, &end)) / runs);

    return 0;
}
