/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _NETD_NETWORKCONTROLLER_H
#define _NETD_NETWORKCONTROLLER_H

#include <list>
#include <map>
#include <string>

#include <stddef.h>
#include <stdint.h>
#include <utils/RWLock.h>

/*
 * Keeps track of default, per-pid, and per-uid-range network selection, as
 * well as the mark associated with each network. Networks are identified
 * by netid. In all set* commands netid == 0 means "unspecified" and is
 * equivalent to clearing the mapping.
 */
class NetworkController {
public:
    NetworkController();

    void setDefaultNetwork(int netid);
    void setNetworkForPid(int pid, int netid);
    // Returns false if a partially overlapping range exists.
    bool setNetworkForUidRange(int uid_start, int uid_end, int netid,
                               bool forward_dns);
    void clearNetworkPreference();

    int getDefaultNetwork() const;
    // Order of preference: UID-specific, netid, PID-specific, default.
    int getNetwork(int uid, int netid, int pid, bool for_dns) const;

    int getNetworkId(const char* interface);

private:
    struct UidEntry {
        int uid_start;
        int uid_end;
        int netid;
        bool forward_dns;
        UidEntry(int uid_start, int uid_end, int netid, bool forward_dns);
    };

    mutable android::RWLock mRWLock;
    std::list<UidEntry> mUidMap;
    std::map<int, int> mPidMap;
    int mDefaultNetId;

    std::map<std::string, int> mIfaceNetidMap;
    int mNextFreeNetid;
};

#endif
