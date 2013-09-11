/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _DNSPROXYLISTENER_H__
#define _DNSPROXYLISTENER_H__

#include <sysutils/FrameworkListener.h>

#include "NetdCommand.h"
#include "UidMarkMap.h"

class DnsProxyWorkerPool;

class DnsProxyListener : public FrameworkListener {
public:
    DnsProxyListener(UidMarkMap *map);
    virtual ~DnsProxyListener();

    friend class DnsProxyJob;
private:
    UidMarkMap *mUidMarkMap;
    DnsProxyWorkerPool* mWorkerPool;

    class DnsProxyHandler {
    public:
        DnsProxyHandler(SocketClient* c);
        virtual ~DnsProxyHandler();
        virtual void run() = 0;

    protected:
        SocketClient* mClient; // ref counted
    };

    class GetAddrInfoCmd : public NetdCommand {
    public:
        GetAddrInfoCmd(UidMarkMap *uidMarkMap, DnsProxyWorkerPool* workerPool);
        virtual ~GetAddrInfoCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    private:
        UidMarkMap *mUidMarkMap;
        DnsProxyWorkerPool* mWorkerPool; // not owned
    };

    class GetAddrInfoHandler : public DnsProxyHandler {
    public:
        // Note: All of host, service, and hints may be NULL
        GetAddrInfoHandler(SocketClient *c,
                           char* host,
                           char* service,
                           struct addrinfo* hints,
                           char* iface,
                           pid_t pid,
                           uid_t uid,
                           int mark);
        ~GetAddrInfoHandler();

        void run();
    private:
        char* mHost;    // owned
        char* mService; // owned
        struct addrinfo* mHints;  // owned
        char* mIface; // owned
        pid_t mPid;
        uid_t mUid;
        int mMark;
    };

    /* ------ gethostbyname ------*/
    class GetHostByNameCmd : public NetdCommand {
    public:
        GetHostByNameCmd(UidMarkMap *uidMarkMap, DnsProxyWorkerPool* workerPool);
        virtual ~GetHostByNameCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    private:
        UidMarkMap *mUidMarkMap;
        DnsProxyWorkerPool* mWorkerPool; // not owned
    };

    class GetHostByNameHandler : public DnsProxyHandler {
    public:
        GetHostByNameHandler(SocketClient *c,
                            pid_t pid,
                            uid_t uid,
                            char *iface,
                            char *name,
                            int af,
                            int mark);
        ~GetHostByNameHandler();

        void run();
    private:
        pid_t mPid;
        uid_t mUid;
        char* mIface; // owned
        char* mName; // owned
        int mAf;
        int mMark;
    };

    /* ------ gethostbyaddr ------*/
    class GetHostByAddrCmd : public NetdCommand {
    public:
        GetHostByAddrCmd(UidMarkMap *uidMarkMap, DnsProxyWorkerPool* workerPool);
        virtual ~GetHostByAddrCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);
    private:
        UidMarkMap *mUidMarkMap;
        DnsProxyWorkerPool* mWorkerPool; // not owned
    };

    class GetHostByAddrHandler : public DnsProxyHandler {
    public:
        GetHostByAddrHandler(SocketClient *c,
                            void* address,
                            int   addressLen,
                            int   addressFamily,
                            char* iface,
                            pid_t pid,
                            uid_t uid,
                            int mark);
        ~GetHostByAddrHandler();

        void run();

    private:
        void* mAddress;    // address to lookup; owned
        int   mAddressLen; // length of address to look up
        int   mAddressFamily;  // address family
        char* mIface; // owned
        pid_t mPid;
        uid_t mUid;
        int   mMark;
    };
};

#endif
