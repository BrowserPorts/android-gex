// The emulator image's own OpenGL ES (its vendor libEGL_emulation and
// libGLESv2_emulation, gfxstream's guest) drawing through gex: its EGL
// reaches the host renderer over the goldfish pipe, its pbuffer is a host
// color buffer; a clear and a read back. Run inside the image's root
// (--sysroot) as root, with GEX_EMULATOR_HOST=1: the drivers are loaded
// by path (with no property service, Android's EGL loader would not find
// them), and /dev is made here as ueventd would make it.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

typedef void *EGLDisplay, *EGLConfig, *EGLSurface, *EGLContext;
typedef int32_t EGLint;
#define EGL_NONE 0x3038
#define EGL_RED_SIZE 0x3024
#define EGL_GREEN_SIZE 0x3023
#define EGL_BLUE_SIZE 0x3022
#define EGL_ALPHA_SIZE 0x3021
#define EGL_SURFACE_TYPE 0x3033
#define EGL_PBUFFER_BIT 0x0001
#define EGL_RENDERABLE_TYPE 0x3040
#define EGL_OPENGL_ES2_BIT 0x0004
#define EGL_WIDTH 0x3057
#define EGL_HEIGHT 0x3056
#define EGL_CONTEXT_CLIENT_VERSION 0x3098
#define EGL_VERSION 0x3054
#define GL_COLOR_BUFFER_BIT 0x4000
#define GL_RGBA 0x1908
#define GL_UNSIGNED_BYTE 0x1401
#define GL_VERSION 0x1F02
#define GL_RENDERER 0x1F01

// logd's socket: liblog's records (id, tid, time, then priority, tag,
// message), printed, so the drivers' own words are seen.
static void *logd(void *arg) {
    int fd = *(int *)arg;
    char b[4200];
    for (;;) {
        long n = recv(fd, b, sizeof b - 1, 0);
        if (n <= 11) {
            continue;
        }
        b[n] = 0;
        const char *tag = b + 12;
        const char *msg = tag + strlen(tag) + 1;
        if (msg < b + n) {
            printf("log %d %s: %s\n", b[11], tag, msg);
            fflush(stdout);
        }
    }
    return NULL;
}

static void *sym(void *lib, const char *name) {
    void *p = dlsym(lib, name);
    if (!p) {
        printf("emugl: no %s\n", name);
    }
    return p;
}

int main(int argc, char **argv) {
    // The drivers load their GLES libraries by name, which a boot's linker
    // finds in the sphal namespace (/vendor/lib64/egl); with no linker
    // configuration here, the default namespace is given those paths.
    if (!getenv("LD_LIBRARY_PATH")) {
        setenv("LD_LIBRARY_PATH", "/vendor/lib64/egl:/vendor/lib64", 1);
        execv("/proc/self/exe", argv);
        printf("emugl: re-exec (errno %d)\n", errno);
        return 1;
    }
    (void)argc;
    // /dev as ueventd leaves it for these drivers.
    if (mount("tmpfs", "/dev", "tmpfs", 0, "mode=0755")) {
        printf("emugl: /dev (errno %d)\n", errno);
        return 1;
    }
    struct { const char *name; int major, minor; } nodes[] = {
        {"/dev/null", 1, 3}, {"/dev/zero", 1, 5}, {"/dev/urandom", 1, 9}, {"/dev/random", 1, 8},
        {"/dev/goldfish_pipe_dprctd", 10, 256}, {"/dev/goldfish_address_space", 10, 257}, {"/dev/goldfish_sync", 10, 258},
    };
    for (unsigned i = 0; i < sizeof nodes / sizeof nodes[0]; i++) {
        if (mknod(nodes[i].name, S_IFCHR | 0666, makedev(nodes[i].major, nodes[i].minor))) {
            printf("emugl: mknod %s (errno %d)\n", nodes[i].name, errno);
            return 1;
        }
    }

    mkdir("/dev/socket", 0755);
    static int log_fd;
    log_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, "/dev/socket/logdw");
    if (log_fd >= 0 && bind(log_fd, (struct sockaddr *)&a, sizeof a) == 0) {
        pthread_t t;
        pthread_create(&t, NULL, logd, &log_fd);
    }
    void *egl = dlopen("/vendor/lib64/egl/libEGL_emulation.so", RTLD_NOW);
    void *gles = dlopen("/vendor/lib64/egl/libGLESv2_emulation.so", RTLD_NOW);
    if (!egl || !gles) {
        printf("emugl: dlopen: %s\n", dlerror());
        return 1;
    }
    EGLDisplay (*getDisplay)(void *) = sym(egl, "eglGetDisplay");
    unsigned (*initialize)(EGLDisplay, EGLint *, EGLint *) = sym(egl, "eglInitialize");
    const char *(*queryString)(EGLDisplay, EGLint) = sym(egl, "eglQueryString");
    unsigned (*chooseConfig)(EGLDisplay, const EGLint *, EGLConfig *, EGLint, EGLint *) = sym(egl, "eglChooseConfig");
    EGLSurface (*createPbuffer)(EGLDisplay, EGLConfig, const EGLint *) = sym(egl, "eglCreatePbufferSurface");
    EGLContext (*createContext)(EGLDisplay, EGLConfig, EGLContext, const EGLint *) = sym(egl, "eglCreateContext");
    unsigned (*makeCurrent)(EGLDisplay, EGLSurface, EGLSurface, EGLContext) = sym(egl, "eglMakeCurrent");
    EGLint (*eglError)(void) = sym(egl, "eglGetError");
    void (*clearColor)(float, float, float, float) = sym(gles, "glClearColor");
    void (*clear)(unsigned) = sym(gles, "glClear");
    void (*readPixels)(int, int, int, int, unsigned, unsigned, void *) = sym(gles, "glReadPixels");
    const char *(*getString)(unsigned) = sym(gles, "glGetString");
    unsigned (*glError)(void) = sym(gles, "glGetError");
    if (!getDisplay || !initialize || !chooseConfig || !createPbuffer || !createContext || !makeCurrent || !clearColor || !clear || !readPixels || !getString || !glError) {
        return 1;
    }

    EGLDisplay dpy = getDisplay(0);
    EGLint major = 0, minor = 0;
    if (!initialize(dpy, &major, &minor)) {
        printf("emugl: eglInitialize: %#x\n", eglError());
        usleep(200000);
        return 1;
    }
    printf("emugl: EGL %d.%d %s\n", major, minor, queryString(dpy, EGL_VERSION));
    EGLint attrs[] = {EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE};
    EGLConfig cfg;
    EGLint n = 0;
    if (!chooseConfig(dpy, attrs, &cfg, 1, &n) || n < 1) {
        printf("emugl: no config (%#x)\n", eglError());
        return 1;
    }
    EGLint pb[] = {EGL_WIDTH, 16, EGL_HEIGHT, 16, EGL_NONE};
    EGLSurface surf = createPbuffer(dpy, cfg, pb);
    EGLint ca[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    EGLContext ctx = createContext(dpy, cfg, 0, ca);
    if (!surf || !ctx || !makeCurrent(dpy, surf, surf, ctx)) {
        printf("emugl: surface %p context %p: %#x\n", surf, ctx, eglError());
        return 1;
    }
    printf("emugl: %s / %s\n", getString(GL_VERSION), getString(GL_RENDERER));
    clearColor(1.0f, 0.5f, 0.0f, 1.0f);
    clear(GL_COLOR_BUFFER_BIT);
    uint8_t px[16 * 16 * 4];
    memset(px, 0x55, sizeof px);
    readPixels(0, 0, 16, 16, GL_RGBA, GL_UNSIGNED_BYTE, px);
    unsigned err = glError();
    int ok = err == 0;
    for (int i = 0; i < 16 * 16; i++) {
        if (px[i * 4] != 255 || px[i * 4 + 1] < 127 || px[i * 4 + 1] > 128 || px[i * 4 + 2] != 0 || px[i * 4 + 3] != 255) {
            ok = 0;
        }
    }
    if (!ok) {
        printf("emugl: GL error %#x, pixel 0 is %d %d %d %d\n", err, px[0], px[1], px[2], px[3]);
        return 1;
    }
    printf("emugl ok\n");
    return 0;
}
