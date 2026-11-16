// A program that aborts with a message: bionic's android_set_abort_message,
// which every LOG(FATAL) and failed CHECK of Android's goes through, keeps
// the text for a crash dumper to find. gexc says it with the crash
// (run.sh looks for it in what gexc printed): Android's own dumper reads
// the dying process with ptrace, and a daemon that aborted during boot
// otherwise said nothing anyone could see.
#include <android/set_abort_message.h>
#include <stdlib.h>

int main(void) {
    android_set_abort_message("the reason it gave");
    abort();
}
