/* Textures shared between two wgl contexts, as Qt's QQuickWidget and
 * QOpenGLWidget use them: context B renders into a framebuffer object whose
 * colour is a texture, and context A, which shares B's objects, draws that
 * texture into the window; A's pixels are read back. Three ways to share:
 * wglShareLists before B makes any object, wglShareLists with A's texture
 * made first (the texture made in A, rendered into from B), and
 * wglCreateContextAttribsARB with A as the share context. Then what is not
 * shared stays each context's own: B's clear colour, bound texture,
 * framebuffer binding, viewport and enables are not A's. Each prints "ok
 * NAME" or "FAIL NAME (got R,G,B)", then "N failures".
 * gex-nt-cc: clang --target=ARCH-w64-mingw32 -fuse-ld=lld -lgdi32 -lopengl32 */
#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>
#include <stdlib.h>

#define GL_FRAMEBUFFER 0x8D40
#define GL_COLOR_ATTACHMENT0 0x8CE0
#define GL_FRAMEBUFFER_COMPLETE 0x8CD5
#define WGL_CONTEXT_MAJOR_VERSION_ARB 0x2091
#define WGL_CONTEXT_MINOR_VERSION_ARB 0x2092
#define WGL_CONTEXT_PROFILE_MASK_ARB 0x9126
#define WGL_CONTEXT_COMPATIBILITY_PROFILE_BIT_ARB 0x0002

#define PROC(ret, name, args) typedef ret (WINAPI *name##_t) args; static name##_t p##name;
PROC(void, glGenFramebuffers, (GLsizei, GLuint *))
PROC(void, glBindFramebuffer, (GLenum, GLuint))
PROC(void, glFramebufferTexture2D, (GLenum, GLenum, GLenum, GLuint, GLint))
PROC(GLenum, glCheckFramebufferStatus, (GLenum))
PROC(void, glDeleteFramebuffers, (GLsizei, const GLuint *))
PROC(HGLRC, wglCreateContextAttribsARB, (HDC, HGLRC, const int *))

static int failures;
static HDC dc;

static GLuint make_texture(void) {
    GLuint t;
    glGenTextures(1, &t);
    glBindTexture(GL_TEXTURE_2D, t);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 64, 64, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glBindTexture(GL_TEXTURE_2D, 0);
    return t;
}

/* in B: the texture cleared to the colour through a framebuffer object */
static int render_into(GLuint t, float r, float g, float b) {
    GLuint fb;
    pglGenFramebuffers(1, &fb);
    pglBindFramebuffer(GL_FRAMEBUFFER, fb);
    pglFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t, 0);
    int complete = pglCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
    glViewport(0, 0, 64, 64);
    glClearColor(r, g, b, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    pglBindFramebuffer(GL_FRAMEBUFFER, 0);
    pglDeleteFramebuffers(1, &fb);
    /* what Qt does before another context samples the texture */
    glFlush();
    return complete;
}

/* in A: the texture drawn over the whole window, its middle pixel read back */
static void sample(const char *name, GLuint t, int R, int G, int B) {
    glViewport(0, 0, 64, 64);
    glClearColor(0, 0, 0, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    glEnable(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, t);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_REPLACE);
    glBegin(GL_QUADS);
    glTexCoord2f(0, 0); glVertex2f(-1, -1);
    glTexCoord2f(1, 0); glVertex2f(1, -1);
    glTexCoord2f(1, 1); glVertex2f(1, 1);
    glTexCoord2f(0, 1); glVertex2f(-1, 1);
    glEnd();
    glDisable(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, 0);
    unsigned char px[4] = {0};
    glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, px);
    int ok = abs(px[0] - R) < 8 && abs(px[1] - G) < 8 && abs(px[2] - B) < 8;
    if (ok) printf("ok %s\n", name);
    else { printf("FAIL %s (got %d,%d,%d, want %d,%d,%d)\n", name, px[0], px[1], px[2], R, G, B); failures++; }
    fflush(stdout);
}

static void check(const char *name, int cond) {
    printf("%s %s\n", cond ? "ok" : "FAIL", name);
    fflush(stdout);
    if (!cond) failures++;
}

int main(void) {
    WNDCLASSW wc = {0};
    wc.style = CS_OWNDC;
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"gex_glshare";
    RegisterClassW(&wc);
    HWND w = CreateWindowExW(0, L"gex_glshare", L"gex gl share", WS_POPUP | WS_VISIBLE, 0, 0, 64, 64, 0, 0, wc.hInstance, 0);
    dc = GetDC(w);
    PIXELFORMATDESCRIPTOR pfd = {sizeof pfd, 1, PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, PFD_TYPE_RGBA, 32};
    SetPixelFormat(dc, ChoosePixelFormat(dc, &pfd), &pfd);

    HGLRC a = wglCreateContext(dc);
    wglMakeCurrent(dc, a);
#define LOAD(name) p##name = (name##_t)wglGetProcAddress(#name)
    LOAD(glGenFramebuffers); LOAD(glBindFramebuffer); LOAD(glFramebufferTexture2D);
    LOAD(glCheckFramebufferStatus); LOAD(glDeleteFramebuffers); LOAD(wglCreateContextAttribsARB);
    if (!pglGenFramebuffers || !pglBindFramebuffer || !pglFramebufferTexture2D || !pglCheckFramebufferStatus) {
        printf("FAIL framebuffer objects: no entry points\n1 failures\n");
        return 1;
    }

    /* 1. wglShareLists(A, B) before B makes anything; the texture made in B */
    {
        HGLRC b = wglCreateContext(dc);
        check("wglShareLists(A, B)", wglShareLists(a, b));
        wglMakeCurrent(dc, b);
        GLuint t = make_texture();
        check("B's framebuffer object on its texture is complete", render_into(t, 10 / 255.f, 200 / 255.f, 30 / 255.f));
        wglMakeCurrent(dc, a);
        check("A sees B's texture name (glIsTexture)", glIsTexture(t));
        sample("A samples the texture B rendered (shared with wglShareLists)", t, 10, 200, 30);
        glDeleteTextures(1, &t);
        wglMakeCurrent(0, 0);
        wglDeleteContext(b);
        wglMakeCurrent(dc, a);
    }
    /* 2. the texture made in A, rendered into from B */
    {
        GLuint t = make_texture();
        HGLRC b = wglCreateContext(dc);
        check("wglShareLists(A, B) (A has objects)", wglShareLists(a, b));
        wglMakeCurrent(dc, b);
        check("B's framebuffer object on A's texture is complete", render_into(t, 200 / 255.f, 60 / 255.f, 20 / 255.f));
        wglMakeCurrent(dc, a);
        sample("A samples its own texture after B rendered into it", t, 200, 60, 20);
        glDeleteTextures(1, &t);
        wglMakeCurrent(0, 0);
        wglDeleteContext(b);
        wglMakeCurrent(dc, a);
    }
    /* 3. B made with A as its share context (Qt's QOpenGLContext::setShareContext) */
    if (pwglCreateContextAttribsARB) {
        const int attrs[] = {WGL_CONTEXT_MAJOR_VERSION_ARB, 3, WGL_CONTEXT_MINOR_VERSION_ARB, 0,
                             WGL_CONTEXT_PROFILE_MASK_ARB, WGL_CONTEXT_COMPATIBILITY_PROFILE_BIT_ARB, 0};
        HGLRC b = pwglCreateContextAttribsARB(dc, a, attrs);
        check("wglCreateContextAttribsARB with a share context", b != 0);
        if (b) {
            wglMakeCurrent(dc, b);
            GLuint t = make_texture();
            check("B's framebuffer object is complete (attribs share)", render_into(t, 40 / 255.f, 60 / 255.f, 210 / 255.f));
            wglMakeCurrent(dc, a);
            sample("A samples the texture B rendered (shared at creation)", t, 40, 60, 210);
            glDeleteTextures(1, &t);
            wglMakeCurrent(0, 0);
            wglDeleteContext(b);
        }
    } else check("wglCreateContextAttribsARB is there", 0);

    /* 4. state is each context's own (only objects are shared) */
    {
        wglMakeCurrent(dc, a);
        GLuint ta = make_texture();
        glClearColor(1, 0, 0, 1);
        glBindTexture(GL_TEXTURE_2D, ta);
        glViewport(1, 2, 30, 40);
        glDisable(GL_BLEND);
        HGLRC b = wglCreateContext(dc);
        wglShareLists(a, b);
        wglMakeCurrent(dc, b);
        GLuint tb = make_texture(), fb;
        glClearColor(0, 1, 0, 1);
        glBindTexture(GL_TEXTURE_2D, tb);
        glViewport(5, 6, 7, 8);
        glEnable(GL_BLEND);
        pglGenFramebuffers(1, &fb);
        pglBindFramebuffer(GL_FRAMEBUFFER, fb);
        pglFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tb, 0);
        wglMakeCurrent(dc, a);
        float cc[4] = {0};
        GLint bound = 0, fbo = -1, vp[4] = {0};
        glGetFloatv(GL_COLOR_CLEAR_VALUE, cc);
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &bound);
        glGetIntegerv(0x8CA6 /* GL_DRAW_FRAMEBUFFER_BINDING */, &fbo);
        glGetIntegerv(GL_VIEWPORT, vp);
        check("A's clear colour is its own after B set one", cc[0] == 1 && cc[1] == 0);
        check("A's bound texture is its own after B bound one", bound == (GLint)ta);
        check("A's framebuffer binding is its own after B bound an FBO", fbo == 0);
        check("A's viewport is its own after B set one", vp[0] == 1 && vp[1] == 2 && vp[2] == 30 && vp[3] == 40);
        check("A's blend enable is its own after B enabled it", !glIsEnabled(GL_BLEND));
        wglMakeCurrent(dc, b);
        pglBindFramebuffer(GL_FRAMEBUFFER, 0);
        pglDeleteFramebuffers(1, &fb);
        glDeleteTextures(1, &tb);
        wglMakeCurrent(dc, a);
        glDeleteTextures(1, &ta);
        wglMakeCurrent(0, 0);
        wglDeleteContext(b);
    }

    wglMakeCurrent(0, 0);
    wglDeleteContext(a);
    printf("%d failures\n", failures);
    return failures != 0;
}
