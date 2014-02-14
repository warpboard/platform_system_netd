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

#define LOG_TAG "NetworkController"
#include <cutils/log.h>

#include "NetworkController.h"

// Mark 1 is reserved for SecondaryTableController::PROTECT_MARK.
NetworkController::NetworkController() : mNextFreeNetid(10) {}

void NetworkController::setDefaultNetwork(int netid) {
    // TODO(szym): assert netid > 0?
    android::RWLock::AutoWLock lock(mRWLock);
    mDefaultNetId = netid;
}

void NetworkController::setNetworkForPid(int pid, int netid) {
    android::RWLock::AutoWLock lock(mRWLock);
    if (netid == 0) {
        mPidMap.erase(pid);
    } else {
        mPidMap[pid] = netid;
    }
}

bool NetworkController::setNetworkForUidRange(int uid_start, int uid_end,
                                              int netid, bool forward_dns) {
    android::RWLock::AutoWLock lock(mRWLock);
    if (uid_start > uid_end)
        return false;

    for (std::list<UidEntry>::iterator it = mUidMap.begin();
         it != mUidMap.end();
         ++it) {
        if (it->uid_start > uid_end || uid_start > it->uid_end)
            continue;
        /* Overlapping or identical range. */
        if (it->uid_start != uid_start || it->uid_end != uid_end) {
            ALOGE("Overlapping but not identical uid range detected.");
            return false;
        }

        if (netid == 0) {
            mUidMap.erase(it);
        } else {
            it->netid = netid;
            it->forward_dns = forward_dns;
        }
        return true;
    }

    mUidMap.push_back(UidEntry(uid_start, uid_end, netid, forward_dns));
    return true;
}

void NetworkController::clearNetworkPreference() {
    android::RWLock::AutoWLock lock(mRWLock);
    mUidMap.clear();
    mPidMap.clear();
}

int NetworkController::getDefaultNetwork() const {
    return mDefaultNetId;
}

int NetworkController::getNetwork(int uid, int netid, int pid,
                                  bool for_dns) const {
    android::RWLock::AutoRLock lock(mRWLock);
    for (std::list<UidEntry>::const_iterator it = mUidMap.begin();
         it != mUidMap.end(); ++it) {
        if (uid < it->uid_start || it->uid_end < uid)
            continue;
        if (for_dns && !it->forward_dns)
            break;
        return it->netid;
    }
    if (netid)
        return netid;
    std::map<int, int>::const_iterator it = mPidMap.find(pid);
    if (it != mPidMap.end())
        return it->second;
    return mDefaultNetId;
}

int NetworkController::getNetworkId(const char* interface) {
    std::map<std::string, int>::const_iterator it =
        mIfaceNetidMap.find(interface);
    if (it != mIfaceNetidMap.end())
        return it->second;

    int netid = mNextFreeNetid++;
    mIfaceNetidMap[interface] = netid;
    return netid;
}

NetworkController::UidEntry::UidEntry(
    int start, int end, int netid, bool forward_dns)
      : uid_start(start),
        uid_end(end),
        netid(netid),
        forward_dns(forward_dns) {
}