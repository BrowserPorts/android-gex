// Calls to Android's servicemanager, made by hand: the binder context
// manager of a device, the real one, asked what libbinder would ask it.
//
// - PING_TRANSACTION: it answers, with nothing.
// - INTERFACE_TRANSACTION: its interface's name, android.os.IServiceManager.
// - listServices: the services it has, "manager" (itself) among them.
// - checkService("manager"): a binder, which arrives as a handle, the
//   first this process has; and of a name it has not, no binder.
//
// libbinder is not used, since its own start waits on a property only
// init's property service sets (servicemanager.ready). The calls are as
// libbinder writes them: the interface token (strict mode policy, work
// source, the 'SYST' header, the name in UTF-16), then the arguments.
//
// Needs a servicemanager on /dev/binder. Without the device the program
// says so and exits 77; with no manager on it the first call fails
// (BR_DEAD_REPLY), which it also says.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAP_SIZE (1 << 20)
#define PACK(a, b, c, d) ((uint32_t)(a) << 24 | (uint32_t)(b) << 16 | (uint32_t)(c) << 8 | (uint32_t)(d))
#define PING_TRANSACTION PACK('_', 'P', 'N', 'G')
#define INTERFACE_TRANSACTION PACK('_', 'N', 'T', 'F')
// IServiceManager.aidl's methods, in its order from 1.
#define CHECK_SERVICE 3
#define LIST_SERVICES 6
#define DUMP_FLAG_PRIORITY_ALL 15
#define DESCRIPTOR "android.os.IServiceManager"

static int fd;
static void *map;

static void die(const char *what, long a, long b) {
    printf("smcall: %s (%ld, %ld; errno %d)\n", what, a, b, errno);
    exit(1);
}

// A parcel being written.
struct parcel {
    uint8_t data[1024];
    size_t len;
};

static void put32(struct parcel *p, uint32_t v) {
    memcpy(p->data + p->len, &v, 4);
    p->len += 4;
}

// A String16: its length in code units, the units, a terminator, padded
// to four bytes.
static void put_string16(struct parcel *p, const char *s) {
    size_t n = strlen(s);
    put32(p, n);
    for (size_t i = 0; i <= n; i++) {
        uint16_t c = i < n ? (uint8_t)s[i] : 0;
        memcpy(p->data + p->len, &c, 2);
        p->len += 2;
    }
    while (p->len % 4) p->data[p->len++] = 0;
}

static void put_token(struct parcel *p) {
    put32(p, 1u << 31);              // strict mode policy: none, gathered
    put32(p, (uint32_t)-1);          // no work source
    put32(p, PACK('S', 'Y', 'S', 'T')); // the system's header
    put_string16(p, DESCRIPTOR);
}

// A reply, copied out of the mapping: its data and its objects' offsets.
struct reply {
    uint8_t data[4096];
    size_t len;
    uint64_t offsets[8];
    size_t objects;
    size_t at;
};

static uint32_t get32(struct reply *r) {
    uint32_t v;
    if (r->at + 4 > r->len) die("a reply too short", r->at, r->len);
    memcpy(&v, r->data + r->at, 4);
    r->at += 4;
    return v;
}

// A String16 as ASCII into out; -1 for a null string.
static int get_string16(struct reply *r, char *out, size_t size) {
    int32_t n = (int32_t)get32(r);
    if (n < 0) return -1;
    if ((size_t)n >= size || r->at + ((size_t)n + 1) * 2 > r->len) die("a string too long", n, r->len);
    for (int i = 0; i < n; i++) {
        uint16_t c;
        memcpy(&c, r->data + r->at + i * 2, 2);
        out[i] = c < 128 ? (char)c : '?';
    }
    out[n] = 0;
    r->at += ((size_t)n + 1) * 2;
    r->at = (r->at + 3) & ~(size_t)3;
    return n;
}

// One call to handle 0, and its reply.
static void call(uint32_t code, struct parcel *p, struct reply *r) {
    struct {
        uint32_t cmd;
        struct binder_transaction_data t;
    } __attribute__((packed)) send;
    memset(&send, 0, sizeof send);
    send.cmd = BC_TRANSACTION;
    send.t.target.handle = 0;
    send.t.code = code;
    send.t.flags = TF_ACCEPT_FDS;
    send.t.data_size = p->len;
    send.t.data.ptr.buffer = (uintptr_t)p->data;
    struct binder_write_read bwr = {.write_size = sizeof send, .write_buffer = (uintptr_t)&send};
    int done = 0, complete = 0;
    while (!done) {
        uint32_t back[64];
        bwr.read_size = sizeof back;
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t)back;
        if (ioctl(fd, BINDER_WRITE_READ, &bwr)) die("BINDER_WRITE_READ", code, 0);
        bwr.write_size = 0;
        for (size_t at = 0; at < bwr.read_consumed;) {
            uint32_t cmd;
            memcpy(&cmd, (uint8_t *)back + at, 4);
            at += 4;
            if (cmd == BR_NOOP) {
            } else if (cmd == BR_TRANSACTION_COMPLETE) {
                complete = 1;
            } else if (cmd == BR_REPLY) {
                struct binder_transaction_data t;
                memcpy(&t, (uint8_t *)back + at, sizeof t);
                at += sizeof t;
                if (!complete) die("a reply before the call was taken", code, 0);
                if (t.data_size > sizeof r->data || t.offsets_size > sizeof r->offsets) die("a reply too big", t.data_size, t.offsets_size);
                // A reply that is only a status: the call failed there.
                if (t.flags & TF_STATUS_CODE) die("the call's status", code, t.data_size >= 4 ? *(int32_t *)(uintptr_t)t.data.ptr.buffer : 0);
                memset(r, 0, sizeof *r);
                r->len = t.data_size;
                memcpy(r->data, (void *)(uintptr_t)t.data.ptr.buffer, t.data_size);
                r->objects = t.offsets_size / 8;
                memcpy(r->offsets, (void *)(uintptr_t)t.data.ptr.offsets, t.offsets_size);
                struct {
                    uint32_t cmd;
                    binder_uintptr_t buffer;
                } __attribute__((packed)) release = {BC_FREE_BUFFER, t.data.ptr.buffer};
                struct binder_write_read w = {.write_size = sizeof release, .write_buffer = (uintptr_t)&release};
                if (ioctl(fd, BINDER_WRITE_READ, &w)) die("BC_FREE_BUFFER", 0, 0);
                done = 1;
            } else if (cmd == BR_DEAD_REPLY) {
                printf("smcall: nothing answers on the device: no servicemanager is its context manager\n");
                exit(1);
            } else if (cmd == BR_FAILED_REPLY) {
                die("the call failed", code, 0);
            } else {
                die("an unexpected return", cmd, code);
            }
        }
    }
}

int main(void) {
    fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("smcall: no /dev/binder: errno %d\n", errno);
        return 77;
    }
    struct binder_version v;
    if (ioctl(fd, BINDER_VERSION, &v) || v.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION) die("BINDER_VERSION", v.protocol_version, 0);
    map = mmap(NULL, MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) die("mmap", 0, 0);

    struct parcel p;
    struct reply r;
    char text[256];

    p.len = 0;
    call(PING_TRANSACTION, &p, &r);
    if (r.len != 0) die("a ping's reply", r.len, 0);
    printf("smcall: it answers a ping\n");

    p.len = 0;
    call(INTERFACE_TRANSACTION, &p, &r);
    if (get_string16(&r, text, sizeof text) < 0 || strcmp(text, DESCRIPTOR)) {
        printf("smcall: its interface is '%s'\n", text);
        return 1;
    }
    printf("smcall: its interface is %s\n", text);

    p.len = 0;
    put_token(&p);
    put32(&p, DUMP_FLAG_PRIORITY_ALL);
    call(LIST_SERVICES, &p, &r);
    int32_t exception = (int32_t)get32(&r);
    if (exception) die("listServices threw", exception, 0);
    int32_t count = (int32_t)get32(&r);
    if (count < 1 || count > 64) die("how many services", count, 0);
    int manager = 0;
    printf("smcall: its services:");
    for (int i = 0; i < count; i++) {
        if (get_string16(&r, text, sizeof text) < 0) die("a null service name", i, 0);
        printf(" %s", text);
        manager += !strcmp(text, "manager");
    }
    printf("\n");
    if (manager != 1) die("manager among its services", manager, count);

    p.len = 0;
    put_token(&p);
    put_string16(&p, "manager");
    call(CHECK_SERVICE, &p, &r);
    exception = (int32_t)get32(&r);
    if (exception) die("checkService threw", exception, 0);
    if (r.objects != 1 || r.offsets[0] != r.at) die("the binder in checkService's reply", r.objects, r.offsets[0]);
    struct flat_binder_object obj;
    memcpy(&obj, r.data + r.at, sizeof obj);
    // The service it registered as "manager" is its own object, which
    // is another node than the one it is context manager by (that one
    // has no address): the first handle this process is given.
    if (obj.hdr.type != BINDER_TYPE_HANDLE || obj.handle != 1) die("the binder's kind and handle", obj.hdr.type, obj.handle);
    printf("smcall: manager is a binder, here handle %u\n", obj.handle);

    p.len = 0;
    put_token(&p);
    put_string16(&p, "no.such.service");
    call(CHECK_SERVICE, &p, &r);
    exception = (int32_t)get32(&r);
    if (exception) die("checkService of nothing threw", exception, 0);
    if (r.objects != 0) die("a binder for a service that is not there", r.objects, 0);
    printf("smcall: no.such.service is not there\n");

    printf("smcall ok\n");
    return 0;
}
