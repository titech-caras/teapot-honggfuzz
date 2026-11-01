/* Target for test-gadget-fds.py: exercise exec remaps and persistent startup. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static void report(int fd, unsigned char input) {
    char record[256];
    int len = snprintf(record, sizeof(record), "TPGADGET 1 1 0x%x\nTPGADGET 2 44 0x%x 10\nTPGADGET 2 45 0x%x 2\n", input, input, input);
    (void)write(fd, record, len);
}

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    const char* value = getenv("HF_TEAPOT_REPORT_FD");
    int fd = value ? atoi(value) : -1;
    struct stat st = {0};
    int rc = fstat(fd, &st);
    FILE* out = fopen(argv[2], "w");
    if (!out) return 3;
    fprintf(out, "%d %d %d\n", fd, rc, !!S_ISFIFO(st.st_mode));
    fclose(out);
    report(fd, 0x41);
    return 0;
}
