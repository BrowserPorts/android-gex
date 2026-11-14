// What frameworks/native/libs/binder/tests/binderDriverInterfaceTest.cpp
// takes from libbinder's <binder/IBinder.h>: the code of a ping. The test
// is of the driver, by ioctl; with this it is built without libbinder.
#pragma once

#include <linux/android/binder.h>

namespace android {

class IBinder {
public:
    enum {
        PING_TRANSACTION = B_PACK_CHARS('_', 'P', 'N', 'G'),
    };
};

} // namespace android
