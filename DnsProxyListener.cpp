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
#include <string.h>
#include <resolv_iface.h>
#include <net/if.h>

#define LOG_TAG "DnsProxyListener"
#define DBG 0

#include <cutils/log.h>
#include <sysutils/SocketClient.h>

#include "DnsProxyListener.h"
#include "ResponseCode.h"

DnsProxyListener::DnsProxyListener() :
                 FrameworkListener("dnsproxyd") {
    registerCmd(new GetAddrInfoCmd());
    registerCmd(new GetHostByAddrCmd());
}

DnsProxyListener::GetAddrInfoHandler::~GetAddrInfoHandler() {
    free(mHost);
    free(mService);
    free(mHints);
    free(mIface);
}

void DnsProxyListener::GetAddrInfoHandler::start() {
    pthread_create(&mThread, NULL,
                   DnsProxyListener::GetAddrInfoHandler::threadStart, this);
}

void* DnsProxyListener::GetAddrInfoHandler::threadStart(void* obj) {
    GetAddrInfoHandler* handler = reinterpret_cast<GetAddrInfoHandler*>(obj);
    handler->run();
    delete handler;
    pthread_exit(NULL);
    return NULL;
}

// Sends 4 bytes of big-endian length, followed by the data.
// Returns true on success.
static bool sendLenAndData(SocketClient *c, const int len, const void* data) {
    uint32_t len_be = htonl(len);
    return c->sendData(&len_be, 4) == 0 &&
        (len == 0 || c->sendData(data, len) == 0);
}

void DnsProxyListener::GetAddrInfoHandler::run() {
    if (DBG) {
        ALOGD("GetAddrInfoHandler, now for %s / %s / %s", mHost, mService, mIface);
    }

    if (mIface == NULL) {
        char tmp[IF_NAMESIZE + 1];
        if (_resolv_get_pids_associated_interface(mPid, tmp, sizeof(tmp)) > 0) {
            mIface = strdup(tmp);
        }
    }
    struct addrinfo* result = NULL;
    uint32_t rv = getaddrinfoforiface(mHost, mService, mHints, mIface, &result);
    if (rv) {
        // getaddrinfo failed
        mClient->sendBinaryMsg(ResponseCode::DnsProxyOperationFailed, &rv, sizeof(rv));
    } else {
        bool success = !mClient->sendCode(ResponseCode::DnsProxyQueryResult);
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
        if (!success) {
            ALOGW("Error writing DNS result to client");
        }
    }
    if (result) {
        freeaddrinfo(result);
    }
    mClient->decRef();
}

DnsProxyListener::GetAddrInfoCmd::GetAddrInfoCmd() :
    NetdCommand("getaddrinfo") {
}

int DnsProxyListener::GetAddrInfoCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (DBG) {
        for (int i = 0; i < argc; i++) {
            ALOGD("argv[%i]=%s", i, argv[i]);
        }
    }
    if (argc != 9) {
        char* msg = NULL;
        asprintf( &msg, "Invalid number of arguments to getaddrinfo: %i", argc);
        ALOGW("%s", msg);
        cli->sendMsg(ResponseCode::CommandParameterError, msg, false);
        free(msg);
        return -1;
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

    char* iface = argv[7];
    if (strcmp(iface, "^") == 0) {
        iface = NULL;
    } else {
        iface = strdup(iface);
    }

    struct addrinfo* hints = NULL;
    int ai_flags = atoi(argv[3]);
    int ai_family = atoi(argv[4]);
    int ai_socktype = atoi(argv[5]);
    int ai_protocol = atoi(argv[6]);
    int pid = atoi(argv[8]);

    if (ai_flags != -1 || ai_family != -1 ||
        ai_socktype != -1 || ai_protocol != -1) {
        hints = (struct addrinfo*) calloc(1, sizeof(struct addrinfo));
        hints->ai_flags = ai_flags;
        hints->ai_family = ai_family;
        hints->ai_socktype = ai_socktype;
        hints->ai_protocol = ai_protocol;
    }

    if (DBG) {
        ALOGD("GetAddrInfoHandler for %s / %s / %s / %d",
             name ? name : "[nullhost]",
             service ? service : "[nullservice]",
             iface ? iface : "[nulliface]",
             pid);
    }

    cli->incRef();
    DnsProxyListener::GetAddrInfoHandler* handler =
        new DnsProxyListener::GetAddrInfoHandler(cli, name, service, hints, iface, pid);
    handler->start();

    return 0;
}

/*******************************************************
 *                  GetHostByAddr                       *
 *******************************************************/
DnsProxyListener::GetHostByAddrCmd::GetHostByAddrCmd() :
        NetdCommand("gethostbyaddr") {
}

int DnsProxyListener::GetHostByAddrCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (DBG) {
        for (int i = 0; i < argc; i++) {
            ALOGD("argv[%i]=%s", i, argv[i]);
        }
    }
    if (argc != 6) {
        char* msg = NULL;
        asprintf(&msg, "Invalid number of arguments to gethostbyaddr: %i", argc);
        ALOGW("%s", msg);
        cli->sendMsg(ResponseCode::CommandParameterError, msg, false);
        free(msg);
        return -1;
    }

    char* addrStr = argv[1];
    int addrLen = atoi(argv[2]);
    int addrFamily = atoi(argv[3]);
    int pid = atoi(argv[4]);

    char* iface = argv[5];
    if (strcmp(iface, "^") == 0) {
        iface = NULL;
    } else {
        iface = strdup(iface);
    }

    void* addr = malloc(sizeof(struct in6_addr));
    errno = 0;
    int result = inet_pton(addrFamily, addrStr, addr);
    if (result <= 0) {
        char* msg = NULL;
        asprintf(&msg, "inet_pton(\"%s\") failed %s", addrStr, strerror(errno));
        ALOGW("%s", msg);
        cli->sendMsg(ResponseCode::OperationFailed, msg, false);
        free(addr);
        free(msg);
        return -1;
    }

    cli->incRef();
    DnsProxyListener::GetHostByAddrHandler* handler =
            new DnsProxyListener::GetHostByAddrHandler(cli, addr, addrLen, addrFamily, iface ,pid);
    handler->start();

    return 0;
}

DnsProxyListener::GetHostByAddrHandler::~GetHostByAddrHandler() {
    free(mAddress);
    free(mIface);
}

void DnsProxyListener::GetHostByAddrHandler::start() {
    pthread_create(&mThread, NULL,
                   DnsProxyListener::GetHostByAddrHandler::threadStart, this);
}

void* DnsProxyListener::GetHostByAddrHandler::threadStart(void* obj) {
    GetHostByAddrHandler* handler = reinterpret_cast<GetHostByAddrHandler*>(obj);
    handler->run();
    delete handler;
    pthread_exit(NULL);
    return NULL;
}

void DnsProxyListener::GetHostByAddrHandler::run() {
    if (DBG) {
        ALOGD("DnsProxyListener::GetHostByAddrHandler::run\n");
    }

    if (mIface == NULL) {
        char tmp[IF_NAMESIZE + 1];
        if (_resolv_get_pids_associated_interface(mPid, tmp, sizeof(tmp)) > 0) {
            mIface = strdup(tmp);
        }
    }

    struct hostent* hp;

    // NOTE gethostbyaddr should take a void* but bionic thinks it should be char*
    hp = gethostbyaddrforiface((char*)mAddress, mAddressLen, mAddressFamily, mIface);

    if (DBG) {
        ALOGD("GetHostByAddrHandler::run gethostbyaddr errno: %s hp->h_name = %s, name_len = %d\n",
                hp ? "success" : strerror(errno),
                (hp && hp->h_name) ? hp->h_name: "null",
                (hp && hp->h_name) ? strlen(hp->h_name)+ 1 : 0);
    }

    bool failed = true;
    if (hp) {
        failed = mClient->sendBinaryMsg(ResponseCode::DnsProxyQueryResult,
                                        hp->h_name ? hp->h_name : "",
                                        hp->h_name ? strlen(hp->h_name)+ 1 : 0);
    } else {
        uint32_t error = h_errno;
        failed = mClient->sendBinaryMsg(ResponseCode::DnsProxyOperationFailed,
                                        &error, sizeof(error));
    }

    if (failed) {
        ALOGW("GetHostByAddrHandler: Error writing DNS result to client\n");
    }
    mClient->decRef();
}
