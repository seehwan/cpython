#define _GNU_SOURCE
#include <stddef.h>              // 👈 offsetof
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

int install_seccomp() {
    struct sock_filter filter[] = {
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        // If syscall == mprotect → kill
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        // Otherwise → allow
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        return -1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        return -1;
    }

    return 0;
}
