// The emulator image's own OpenGL ES (its vendor libEGL_emulation and
// libGLESv2_emulation, gfxstream's guest) drawing through gex: its EGL
// reaches the host renderer over the goldfish pipe, its pbuffer is a host
// color buffer; SurfaceFlinger's start (SkiaGLRenderEngine::create: a
// config by its attributes, a context, a placeholder pbuffer or none as the
// extensions say, made current), then a clear and a read back. Run inside the image's root
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
#define EGL_EXTENSIONS 0x3055
#define EGL_WINDOW_BIT 0x0004
#define EGL_OPENGL_ES3_BIT 0x0040
#define EGL_RECORDABLE_ANDROID 0x3142
#define EGL_FRAMEBUFFER_TARGET_ANDROID 0x3147

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
    // SurfaceFlinger's start. With EGL_KHR_no_config_context it makes its
    // context with no config, and with EGL_KHR_surfaceless_context it makes
    // no placeholder: both then rest on the driver's own choices.
    {
        const char *ext = queryString(dpy, EGL_EXTENSIONS);
        int no_config = ext && strstr(ext, "EGL_KHR_no_config_context");
        int surfaceless = ext && strstr(ext, "EGL_KHR_surfaceless_context");
        EGLConfig sf_cfg = NULL;
        EGLint n = 0;
        if (!no_config) {
            EGLint sf_attrs[] = {EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_RECORDABLE_ANDROID, 1, EGL_SURFACE_TYPE, EGL_WINDOW_BIT | EGL_PBUFFER_BIT, EGL_FRAMEBUFFER_TARGET_ANDROID, 1, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE};
            if (!chooseConfig(dpy, sf_attrs, &sf_cfg, 1, &n) || n < 1) {
                printf("emugl: SurfaceFlinger's config: none (%#x)\n", eglError());
                return 1;
            }
        }
        EGLint sf_ca[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
        EGLContext sf_ctx = createContext(dpy, sf_cfg, 0, sf_ca);
        EGLSurface sf_pb = NULL;
        if (!surfaceless) {
            EGLint one[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};
            sf_pb = createPbuffer(dpy, sf_cfg, one);
        }
        if (!sf_ctx || (!surfaceless && !sf_pb) || !makeCurrent(dpy, sf_pb, sf_pb, sf_ctx)) {
            printf("emugl: SurfaceFlinger's placeholder (no config %d, surfaceless %d): context %p surface %p: %#x\n", !!no_config, !!surfaceless, sf_ctx, sf_pb, eglError());
            return 1;
        }
        makeCurrent(dpy, NULL, NULL, NULL);
    }
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
    // A draw as an app makes one: shaders, a program, a float uniform, a
    // client array of vertices (the encoder sends it as data), the left
    // half of the surface covered.
    unsigned (*createShader)(unsigned) = sym(gles, "glCreateShader");
    void (*shaderSource)(unsigned, int, const char *const *, const int *) = sym(gles, "glShaderSource");
    void (*compileShader)(unsigned) = sym(gles, "glCompileShader");
    void (*getShaderiv)(unsigned, unsigned, int *) = sym(gles, "glGetShaderiv");
    unsigned (*createProgram)(void) = sym(gles, "glCreateProgram");
    void (*attachShader)(unsigned, unsigned) = sym(gles, "glAttachShader");
    void (*bindAttribLocation)(unsigned, unsigned, const char *) = sym(gles, "glBindAttribLocation");
    void (*linkProgram)(unsigned) = sym(gles, "glLinkProgram");
    void (*getProgramiv)(unsigned, unsigned, int *) = sym(gles, "glGetProgramiv");
    void (*useProgram)(unsigned) = sym(gles, "glUseProgram");
    int (*getUniformLocation)(unsigned, const char *) = sym(gles, "glGetUniformLocation");
    void (*uniform4f)(int, float, float, float, float) = sym(gles, "glUniform4f");
    void (*enableAttrib)(unsigned) = sym(gles, "glEnableVertexAttribArray");
    void (*attribPointer)(unsigned, int, unsigned, unsigned char, int, const void *) = sym(gles, "glVertexAttribPointer");
    void (*drawArrays)(unsigned, int, int) = sym(gles, "glDrawArrays");
    const char *vs = "attribute vec2 pos; void main() { gl_Position = vec4(pos, 0.0, 1.0); }";
    const char *fs = "precision mediump float; uniform vec4 color; void main() { gl_FragColor = color; }";
    unsigned sh[2] = {createShader(0x8B31), createShader(0x8B30)};
    const char *src[2] = {vs, fs};
    unsigned prog = createProgram();
    for (int i = 0; i < 2; i++) {
        int compiled = 0;
        shaderSource(sh[i], 1, &src[i], NULL);
        compileShader(sh[i]);
        getShaderiv(sh[i], 0x8B81, &compiled);
        if (!compiled) {
            printf("emugl: shader %d did not compile\n", i);
            return 1;
        }
        attachShader(prog, sh[i]);
    }
    bindAttribLocation(prog, 3, "pos");
    linkProgram(prog);
    int linked = 0;
    getProgramiv(prog, 0x8B82, &linked);
    if (!linked) {
        printf("emugl: the program did not link\n");
        return 1;
    }
    useProgram(prog);
    uniform4f(getUniformLocation(prog, "color"), 0.0f, 1.0f, 0.0f, 1.0f);
    static const float quad[] = {-1, -1, 0, -1, 0, 1, -1, -1, 0, 1, -1, 1};
    enableAttrib(3);
    attribPointer(3, 2, 0x1406, 0, 0, quad);
    clearColor(0.0f, 0.0f, 1.0f, 1.0f);
    clear(GL_COLOR_BUFFER_BIT);
    drawArrays(0x0004, 0, 6);
    readPixels(0, 0, 16, 16, GL_RGBA, GL_UNSIGNED_BYTE, px);
    err = glError();
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            const uint8_t *p = px + (y * 16 + x) * 4;
            int want_green = x < 8;
            if (p[0] != 0 || p[1] != (want_green ? 255 : 0) || p[2] != (want_green ? 0 : 255) || p[3] != 255) {
                ok = 0;
            }
        }
    }
    if (!ok || err) {
        printf("emugl: the draw: GL error %#x, pixel (0,8) %d %d %d, (15,8) %d %d %d\n", err, px[8 * 64], px[8 * 64 + 1], px[8 * 64 + 2], px[8 * 64 + 60], px[8 * 64 + 61], px[8 * 64 + 62]);
        return 1;
    }
    printf("emugl ok\n");
    return 0;
}
