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

#include <pthread.h>
#include <sysutils/FrameworkListener.h>

#include "NetdCommand.h"

#define CONFIG_DNSPROXYWORKERPOOL_MAXTHREADS 10

class DnsProxyListener : public FrameworkListener {
public:
    DnsProxyListener();
    virtual ~DnsProxyListener();

private:
    class DnsProxyHandler {
        public:
        DnsProxyHandler(SocketClient* c) : mClient(c) {}
        virtual ~DnsProxyHandler() {}
        virtual void run();

    protected:
        SocketClient* mClient; // not owned
    };

    class GetAddrInfoHandler : public DnsProxyHandler {
    public:
        // Note: All of host, service, and hints may be NULL
        GetAddrInfoHandler(SocketClient* c,
                           char* host,
                           char* service,
                           struct addrinfo* hints)
            : DnsProxyHandler(c),
              mHost(host),
              mService(service),
              mHints(hints) {}
        ~GetAddrInfoHandler();

        void run();

    private:
        char* mHost;    // owned
        char* mService; // owned
        struct addrinfo* mHints;  // owned
    };

    /* ------ gethostbyaddr ------*/
    class GetHostByAddrHandler : public DnsProxyHandler {
    public:
        GetHostByAddrHandler(SocketClient* c,
                            char* address,
                            int   addressLen,
                            int   addressFamily)
            : DnsProxyHandler(c),
              mAddress(address),
              mAddressLen(addressLen),
              mAddressFamily(addressFamily) {}
        ~GetHostByAddrHandler();

        void run();

    private:
        char* mAddress;    // address to lookup
        int   mAddressLen; // length of address to look up
        int   mAddressFamily;  // address family
    };

    /* DnsProxyJob is holding a reference to a handler
     * that shall handle the job and a reference to the
     * next job in the queue.
     *
     * DnsProxyWorker's queue is populated by DnsProxyJobs
     * */
    class DnsProxyJob {
    public:
        DnsProxyJob(DnsProxyHandler* handler) : mNext(NULL), mHandler(handler){}
        virtual ~DnsProxyJob();

        void execute();
        DnsProxyJob*        mNext;

    private:
        DnsProxyHandler*    mHandler;
    };

    /* DnsProxyWorkerPool implements a queue of
     * DnsProxyJobs and a pool of threads. The thread
     * gets jobs from the queue and execute the
     * job. If there is no job in the queue the
     * threads waits until a new is added. When
     * a new job is added to the queue one of
     * the threads is waken by a signal.
     *
     * A thread is doing its work in doWork method.
     *
     * */
    class DnsProxyWorkerPool {
    public:
        DnsProxyWorkerPool(int noOfThreads);
        virtual ~DnsProxyWorkerPool();

        void shutDown();
        void addJob(DnsProxyJob* job);
        DnsProxyJob* getNextJob();
        bool jobExist();

        pthread_mutex_t     mMutex;
        pthread_cond_t      mJobAdded;
        pthread_cond_t      mWorkStopped;

        int                 mNoOfRunningThreads;
        bool                mWork;

    private:
        static void*        doWork(void* pool);

        int                 mNoOfThreads;
        pthread_t           mThread[CONFIG_DNSPROXYWORKERPOOL_MAXTHREADS];

        DnsProxyJob*        mJobQueue;
    };

    class GetAddrInfoCmd: public NetdCommand {
    public:
        GetAddrInfoCmd(DnsProxyWorkerPool* workerPool);
        virtual ~GetAddrInfoCmd() {
        }
        int runCommand(SocketClient* c, int argc, char** argv);

    private:
        DnsProxyWorkerPool* mWorkerPoolRef;
    };

    class GetHostByAddrCmd: public NetdCommand {
    public:
        GetHostByAddrCmd(DnsProxyWorkerPool* workerPool);
        virtual ~GetHostByAddrCmd() {
        }
        int runCommand(SocketClient* c, int argc, char** argv);

    private:
        DnsProxyWorkerPool* mWorkerPoolRef;
    };

    // member of DnsProxyListener
    DnsProxyWorkerPool*     mWorkerPool;
};

#endif
