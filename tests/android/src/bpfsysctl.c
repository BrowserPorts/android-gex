// The BPF settings Android's network BPF loader (netbpfload) writes before
// anything else, and stops the boot without: kernel.unprivileged_bpf_
// disabled to 0, net.core.bpf_jit_enable and net.core.bpf_jit_kallsyms to
// 1. As Linux has them built with CONFIG_BPF_JIT_ALWAYS_ON and
// CONFIG_BPF_UNPRIV_DEFAULT_OFF:
// - bpf_jit_enable reads 1 and takes only 1;
// - bpf_jit_kallsyms takes 0 or 1;
// - unprivileged_bpf_disabled takes 0 to 2.
// (Once unprivileged_bpf_disabled is 1 it takes nothing else until the
// machine restarts, which is not tried here.) As root; each setting is
// put back as it was.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *what, long got, long want) {
    printf("bpfsysctl: %s: got %ld (errno %d), wanted %ld\n", what, got, errno, want);
    exit(1);
}

static long get(const char *path) {
    char buf[32] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0 || read(fd, buf, sizeof buf - 1) <= 0) fail(path, -errno, 0);
    close(fd);
    return strtol(buf, NULL, 10);
}

// The write's result: 0, or -errno.
static long put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -errno;
    long r = write(fd, text, strlen(text));
    long e = r < 0 ? -errno : 0;
    close(fd);
    return e;
}

static void expect(const char *what, long got, long want) {
    if (got != want) fail(what, got, want);
}

int main(void) {
    const char *jit = "/proc/sys/net/core/bpf_jit_enable";
    const char *kall = "/proc/sys/net/core/bpf_jit_kallsyms";
    const char *unpriv = "/proc/sys/kernel/unprivileged_bpf_disabled";
    expect("bpf_jit_enable", get(jit), 1);
    expect("bpf_jit_enable 0", put(jit, "0\n"), -EINVAL);
    expect("bpf_jit_enable 2", put(jit, "2\n"), -EINVAL);
    expect("bpf_jit_enable 1", put(jit, "1\n"), 0);

    long k = get(kall);
    expect("bpf_jit_kallsyms 2", put(kall, "2\n"), -EINVAL);
    expect("bpf_jit_kallsyms 0", put(kall, "0\n"), 0);
    expect("bpf_jit_kallsyms reads 0", get(kall), 0);
    expect("bpf_jit_kallsyms 1", put(kall, "1\n"), 0);
    expect("bpf_jit_kallsyms reads 1", get(kall), 1);
    put(kall, k ? "1\n" : "0\n");

    long u = get(unpriv);
    if (u == 1) fail("unprivileged_bpf_disabled is 1, which cannot be changed", u, 2);
    expect("unprivileged_bpf_disabled 3", put(unpriv, "3\n"), -EINVAL);
    expect("unprivileged_bpf_disabled -1", put(unpriv, "-1\n"), -EINVAL);
    expect("unprivileged_bpf_disabled 0", put(unpriv, "0\n"), 0);
    expect("unprivileged_bpf_disabled reads 0", get(unpriv), 0);
    expect("unprivileged_bpf_disabled 2", put(unpriv, "2\n"), 0);
    expect("unprivileged_bpf_disabled reads 2", get(unpriv), 2);
    put(unpriv, u == 0 ? "0\n" : "2\n");

    printf("bpfsysctl ok\n");
    return 0;
}
