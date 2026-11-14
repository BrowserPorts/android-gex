// What frameworks/native/libs/binder/tests/binderDriverInterfaceTest.cpp
// takes from libbinder's <binder/ProcessState.h>: whether the driver says
// it has a feature, asked as libbinder asks (readDriverFeatureFile in
// ProcessState.cpp): the first byte of the feature's file in binderfs.
#pragma once

#include <fcntl.h>
#include <unistd.h>

namespace android {

class ProcessState {
public:
    enum class DriverFeature {
        ONEWAY_SPAM_DETECTION,
        EXTENDED_ERROR,
        FREEZE_NOTIFICATION,
    };

    static bool isDriverFeatureEnabled(const DriverFeature feature) {
        const char* file = feature == DriverFeature::ONEWAY_SPAM_DETECTION ? "/dev/binderfs/features/oneway_spam_detection"
                         : feature == DriverFeature::EXTENDED_ERROR ? "/dev/binderfs/features/extended_error"
                         : "/dev/binderfs/features/freeze_notification";
        int fd = open(file, O_RDONLY | O_CLOEXEC);
        if (fd == -1) return false;
        char on = 0;
        bool read_one = read(fd, &on, sizeof(on)) == sizeof(on);
        close(fd);
        return read_one && on == '1';
    }
};

} // namespace android
