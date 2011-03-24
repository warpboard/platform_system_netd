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

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#define LOG_TAG "DnsProxyListener"
#define DBG 0

#include <cutils/log.h>
#include <sysutils/SocketClient.h>

#include "DnsProxyListener.h"

/*******************************************************
 *                  DnsProxyListener                   *
 *******************************************************/
DnsProxyListener::DnsProxyListener() :
                 FrameworkListener("dnsproxyd") {

    mWorkerPool = new DnsProxyWorkerPool(CONFIG_DNSPROXYWORKERPOOL_MAXTHREADS);

    registerCmd(new GetAddrInfoCmd(mWorkerPool));
    registerCmd(new GetHostByAddrCmd(mWorkerPool));
}

DnsProxyListener::~DnsProxyListener() {
    mWorkerPool->shutDown(); // will wait until threads are down
    delete mWorkerPool;
}

DnsProxyListener::GetAddrInfoHandler::~GetAddrInfoHandler() {
    free(mHost);
    free(mService);
    free(mHints);
}

// Sends 4 bytes of big-endian length, followed by the data.
// Returns true on success.
static bool sendLenAndData(SocketClient *c, const int len, const void* data) {
    uint32_t len_be = htonl(len);
    return c->sendData(&len_be, 4) == 0 &&
        (len == 0 || c->sendData(data, len) == 0);
}

/*******************************************************
 *                  GetAddrInfoHandler                 *
 *******************************************************/
void DnsProxyListener::GetAddrInfoHandler::run() {
    if (DBG) {
        LOGD("GetAddrInfoHandler, now for %s / %s", mHost, mService);
    }

    struct addrinfo* result = NULL;
    int rv = getaddrinfo(mHost, mService, mHints, &result);
    bool success = (mClient->sendData(&rv, sizeof(rv)) == 0);
    if (rv == 0) {
        struct addrinfo* ai = result;
        while (ai && success) {
            success = sendLenAndData(mClient, sizeof(struct addrinfo), ai)
                && sendLenAndData(mClient, ai->ai_addrlen, ai->ai_addr)
                && sendLenAndData(mClient,
                                  ai->ai_canonname ? strlen(ai->ai_canonname) + 1 : 0,
                                  ai->ai_canonname);
            ai = ai->ai_next;
        }
        success = success && sendLenAndData(mClient, 0, "");
    }
    if (result) {
        freeaddrinfo(result);
    }
    if (!success) {
        LOGW("Error writing DNS result to client");
    }
}

DnsProxyListener::GetAddrInfoCmd::GetAddrInfoCmd(DnsProxyWorkerPool* workerPool) :
    NetdCommand("getaddrinfo"), mWorkerPool(workerPool) {
}

int DnsProxyListener::GetAddrInfoCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 7) {
        LOGW("Invalid number of arguments to getaddrinfo");
        return 0;
    }

    char* name = argv[1];
    if (strcmp("^", name) == 0) {
        name = NULL;
    } else {
        name = strdup(name);
    }

    char* service = argv[2];
    if (strcmp("^", service) == 0) {
        service = NULL;
    } else {
        service = strdup(service);
    }

    struct addrinfo* hints = NULL;
    int ai_flags = atoi(argv[3]);
    int ai_family = atoi(argv[4]);
    int ai_socktype = atoi(argv[5]);
    int ai_protocol = atoi(argv[6]);
    if (ai_flags != -1 || ai_family != -1 ||
        ai_socktype != -1 || ai_protocol != -1) {
        hints = (struct addrinfo*) calloc(1, sizeof(struct addrinfo));
        hints->ai_flags = ai_flags;
        hints->ai_family = ai_family;
        hints->ai_socktype = ai_socktype;
        hints->ai_protocol = ai_protocol;
    }

    if (DBG) {
        LOGD("GetAddrInfoHandler for %s / %s",
             name ? name : "[nullhost]",
             service ? service : "[nullservice]");
    }

    DnsProxyListener::GetAddrInfoHandler* handler =
            new DnsProxyListener::GetAddrInfoHandler(cli, name, service, hints);

    DnsProxyListener::DnsProxyJob* job =
            new DnsProxyListener::DnsProxyJob::DnsProxyJob(handler);

    mWorkerPool->addJob(job);

    return 0;
}

/*******************************************************
 *                  GetHostByAddr                       *
 *******************************************************/
DnsProxyListener::GetHostByAddrCmd::GetHostByAddrCmd(DnsProxyWorkerPool* workerPool) :
        NetdCommand("gethostbyaddr"), mWorkerPool(workerPool) {
}

int DnsProxyListener::GetHostByAddrCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 4) {
        LOGW("Invalid number of arguments to gethostbyaddr");
        return 0;
    }

    char* addr = argv[1];
    addr = strdup(addr);

    int addrLen = atoi(argv[2]);
    int addrFamily = atoi(argv[3]);

    DnsProxyListener::GetHostByAddrHandler* handler =
            new DnsProxyListener::GetHostByAddrHandler(cli, addr, addrLen, addrFamily);

    DnsProxyListener::DnsProxyJob* job =
            new DnsProxyListener::DnsProxyJob::DnsProxyJob(handler);

    mWorkerPool->addJob(job);

    return 0;
}

DnsProxyListener::GetHostByAddrHandler::~GetHostByAddrHandler() {
    free(mAddress);
}

void DnsProxyListener::GetHostByAddrHandler::run() {
    if (DBG) {
        LOGD("DnsProxyListener::GetHostByAddrHandler::run\n");
        if (mAddress) {
            LOGD("mAdress %u.%u.%u.%u mAdressLen %d, mAddressFamily %d",
                    mAddress[0], mAddress[1], mAddress[2], mAddress[3],
                    mAddressLen, mAddressFamily);
        }
        else {
            LOGD("mAddress = NULL");
        }
    }

    struct hostent* hp;

    hp = gethostbyaddr(mAddress, mAddressLen, mAddressFamily);

    if (DBG) {
        LOGD("GetHostByAddrHandler::run gethostbyaddr errno: %s hp->h_name = %s, name_len = %d\n",
                hp ? "success" : strerror(errno),
                (hp && hp->h_name) ? hp->h_name: "null",
                (hp && hp->h_name) ? strlen(hp->h_name)+ 1 : 0);
    }

    bool success = sendLenAndData(mClient, (hp && hp->h_name) ? strlen(hp->h_name)+ 1 : 0,
            (hp && hp->h_name) ? hp->h_name : "");

    if (!success) {
        LOGW("GetHostByAddrHandler: Error writing DNS result to client\n");
    }
}

/*********************************************************
 *                DnsProxyWorkerPool                     *
 *********************************************************/
DnsProxyListener::DnsProxyWorkerPool::DnsProxyWorkerPool(int numThreads) {

    pthread_mutex_init(&mMutex, NULL);
    pthread_cond_init(&mJobAdded, NULL);
    pthread_cond_init(&mWorkStopped, NULL);

    if (numThreads < 1 || numThreads > CONFIG_DNSPROXYWORKERPOOL_MAXTHREADS) {
        mNumThreads = CONFIG_DNSPROXYWORKERPOOL_MAXTHREADS;
    } else {
        mNumThreads = numThreads;
    }

    mIsRunning = true;

    mNumRunningThreads = 0;

    mJobQueue = new DnsProxyJob(NULL);
    mJobQueue->mNext = NULL;

    for (int i = 0; i < mNumThreads; i++) {
        pthread_create(&mThread[i], NULL,
                DnsProxyListener::DnsProxyWorkerPool::doWork, this);
    }

    if (DBG) {
        LOGD("DnsProxyWorkerPool created\n");
    }
}

DnsProxyListener::DnsProxyWorkerPool::~DnsProxyWorkerPool() {
    delete mJobQueue;
}

void DnsProxyListener::DnsProxyWorkerPool::shutDown() {
    pthread_mutex_lock(&mMutex);
    if (mIsRunning) {
        mIsRunning = false;
        pthread_cond_broadcast(&mJobAdded);
        while (mNumRunningThreads > 0) {
            pthread_cond_wait(&mWorkStopped, &mMutex);
        }
    }
    DnsProxyJob* job;
    while ((job = getNextJob()) != NULL) {
        delete job;
    }
    pthread_mutex_unlock(&mMutex);
}

void* DnsProxyListener::DnsProxyWorkerPool::doWork(void* pool) {
    DnsProxyWorkerPool* tp =
            reinterpret_cast<DnsProxyWorkerPool *> (pool);

    pthread_mutex_lock(&tp->mMutex);
    int id = tp->mNumRunningThreads;
    tp->mNumRunningThreads++;
    pthread_mutex_unlock(&tp->mMutex);

    if (DBG) {
        LOGD("DnsProxyWorker %d is working\n", id);
    }

    while (1) {
        pthread_mutex_lock(&tp->mMutex);

        while (!tp->jobPending() && tp->mIsRunning) {
            if (DBG) {
                LOGD("DnsProxyWorker %d waiting for job\n", id);
            }
            pthread_cond_wait(&tp->mJobAdded, &tp->mMutex);
        }

        if (!tp->mIsRunning) {
            break;
        }

        DnsProxyJob* job = tp->getNextJob();

        pthread_mutex_unlock(&tp->mMutex);

        if (DBG) {
            LOGD("DnsProxyWorker %d is doing a job\n", id);
        }

        job->execute();

        delete job;
    }

    if (DBG) {
        LOGD("DnsProxyWorker %d has stopped working\n", id);
    }

    tp->mNumRunningThreads--;
    pthread_cond_signal(&tp->mWorkStopped);

    pthread_mutex_unlock(&tp->mMutex);

    pthread_exit(NULL);
    return NULL;
}

void DnsProxyListener::DnsProxyWorkerPool::addJob(DnsProxyJob* job) {

    pthread_mutex_lock(&mMutex);

    DnsProxyJob* last;
    for (last = mJobQueue; last->mNext; last = last->mNext);

    last->mNext = job;

    pthread_cond_signal(&mJobAdded);

    pthread_mutex_unlock(&mMutex);
}

DnsProxyListener::DnsProxyJob* DnsProxyListener::DnsProxyWorkerPool::getNextJob() {
    DnsProxyJob* nextJob;

    nextJob = mJobQueue->mNext;
    mJobQueue->mNext = nextJob->mNext;

    return nextJob;
}

bool DnsProxyListener::DnsProxyWorkerPool::jobPending() {
    return mJobQueue->mNext != NULL;
}

/*********************************************************
 *                    DnsProxyJob                        *
 *********************************************************/
void DnsProxyListener::DnsProxyJob::execute() {
    if (mHandler != NULL) {
        mHandler->run();
    }
}

DnsProxyListener::DnsProxyJob::~DnsProxyJob() {
    delete mHandler;
}

/*********************************************************
 *                    DnsProxyHandler                    *
 *********************************************************/
DnsProxyListener::DnsProxyHandler::DnsProxyHandler(SocketClient* c) : mClient(c) {
    mClient->incRef();
}

DnsProxyListener::DnsProxyHandler::~DnsProxyHandler() {
    mClient->decRef();
}
