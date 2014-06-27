/* omhdfs.c
 * This is an output module to support Hadoop's HDFS.
 *
 * NOTE: read comments in module-template.h to understand how this file
 *       works!
 *
 * Copyright 2010-2014 Rainer Gerhards and Adiscon GmbH.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 */

/*
 * TODO:
 * 1. add hdfsUser configuration
 * 2. add DynaFileTemplate
 * 3. v6 style configuration
 * 4. ^
 */

/*
 5389.203243127:7f227971e740: load:  'omhdfs'
5389.203254175:7f227971e740: Requested to load module 'omhdfs'
5389.203260318:7f227971e740: loading module '/usr/home/chunsheng5/rsyslog-v8-stable-bin/lib/rsyslog/omhdfs.so'
5389.205980237:7f227971e740: omhdfs: module compiled with rsyslog version 8.2.2.
5389.205999275:7f227971e740: module omhdfs of type 1 being loaded (keepType=0).
5389.206006406:7f227971e740: entry point 'setModCnf' not present in module
5389.206012132:7f227971e740: entry point 'getModCnfName' not present in module
5389.206017874:7f227971e740: entry point 'beginCnfLoad' not present in module
5389.206026899:7f227971e740: entry point 'SetShutdownImmdtPtr' not present in module
5389.206033732:7f227971e740: entry point 'commitTransaction' not present in module
5389.206039701:7f227971e740: entry point 'newActInst' not present in module
-> $$ = nterm conf ()
Stack now 0
Entering state 1
Reading a token: 5389.206072376:7f227971e740: cnf:global:cfsysline: $FileOwner hadoop
5389.206301222:7f227971e740: uid 1208 obtained for user 'hadoop'
5389.206314120:7f227971e740: cnf:global:cfsysline: $FileGroup hadoop
5389.206379701:7f227971e740: gid 492 obtained for group 'hadoop'
5389.206390321:7f227971e740: cnf:global:cfsysline: $FileCreateMode 0640
5389.206399964:7f227971e740: cnf:global:cfsysline: $DirCreateMode 0755
5389.206407444:7f227971e740: cnf:global:cfsysline: $Umask 0022
5389.206415918:7f227971e740: cnf:global:cfsysline: $OMHDFSFileName /rsyslog_test/testchunsheng.rsyslog.v8.log
5389.206427607:7f227971e740: doGetWord: get newval '/rsyslog_test/testchunsheng.rsyslog.v8.log' (len 42), hdlr (nil)
5389.206434659:7f227971e740: cnf:global:cfsysline: $OMHDFSHost nn2.test.dip.sina.com.cn
5389.206443213:7f227971e740: doGetWord: get newval 'nn2.test.dip.sina.com.cn' (len 24), hdlr (nil)
5389.206449431:7f227971e740: cnf:global:cfsysline: $OMHDFSPort 8020
Next token is token PRIFILT ()
Shifting token PRIFILT ()
Entering state 14
Reading a token: Next token is token LEGACY_ACTION ()
Shifting token LEGACY_ACTION ()
Entering state 12
Reducing stack by rule 35 (line 168):
   $1 = token LEGACY_ACTION ()
5389.206496935:7f227971e740: tried selector action for builtin:omfile: -2001
5389.206504195:7f227971e740: tried selector action for builtin:ompipe: -2001
5389.206512203:7f227971e740: tried selector action for builtin-shell: -2001
5389.206518818:7f227971e740: tried selector action for builtin:omdiscard: -2001
5389.206526994:7f227971e740: tried selector action for builtin:omfwd: -2001
5389.206533822:7f227971e740: tried selector action for builtin:omusrmsg: -2001
5389.206578864:7f227971e740: omhdfs: try to connect to HDFS at host 'nn2.test.dip.sina.com.cn', port 8020
2014-06-25 19:23:09,861 WARN  [main] util.NativeCodeLoader (NativeCodeLoader.java:<clinit>(62)) - Unable to load native-hadoop library for your platform... using builtin-java classes where applicable
hdfsOpenFile(/rsyslog_test/testchunsheng.rsyslog.v8.log): FileSystem#append((Lorg/apache/hadoop/fs/Path;)Lorg/apache/hadoop/fs/FSDataOutputStream;) error:
java.io.FileNotFoundException: failed to append to non-existent file /rsyslog_test/testchunsheng.rsyslog.v8.log on client DFSClient_NONMAPREDUCE_-1624630866_1
        at org.apache.hadoop.hdfs.DFSClient.append(DFSClient.java:1388)
        at org.apache.hadoop.hdfs.DFSClient.append(DFSClient.java:1379)
        at org.apache.hadoop.hdfs.DistributedFileSystem.append(DistributedFileSystem.java:258)
        at org.apache.hadoop.hdfs.DistributedFileSystem.append(DistributedFileSystem.java:82)
        at org.apache.hadoop.fs.FileSystem.append(FileSystem.java:1143)
5390.663656564:7f227971e740: omhdfs: failed to open /rsyslog_test/testchunsheng.rsyslog.v8.log for writing!
5390.663686170:7f227971e740: Called LogMsg, msg: omhdfs: failed to open /rsyslog_test/testchunsheng.rsyslog.v8.log - retrying later
5390.663752429:7f227971e740: omhdfs: file /rsyslog_test/testchunsheng.rsyslog.v8.log now being used by 1 actions
5390.663779845:7f227971e740: tried selector action for omhdfs: -2007
5390.663785899:7f227971e740: error -2007 parsing config line
 
 */
/*
 7731.892887109:7ffc9682b740: Requested to load module 'omhdfs'
7731.892893112:7ffc9682b740: loading module '/usr/home/chunsheng5/rsyslog-v8-stable-bin/lib/rsyslog/omhdfs.so'
7731.895609420:7ffc9682b740: omhdfs: module compiled with rsyslog version 8.2.2.
7731.895623486:7ffc9682b740: module omhdfs of type 1 being loaded (keepType=0).
7731.895630710:7ffc9682b740: entry point 'setModCnf' not present in module
7731.895636270:7ffc9682b740: entry point 'getModCnfName' not present in module
7731.895641753:7ffc9682b740: entry point 'beginCnfLoad' not present in module
7731.895650246:7ffc9682b740: entry point 'SetShutdownImmdtPtr' not present in module
7731.895656586:7ffc9682b740: entry point 'commitTransaction' not present in module
7731.895662261:7ffc9682b740: entry point 'newActInst' not present in module
-> $$ = nterm conf ()
Stack now 0
Entering state 1
Reading a token: 7731.895689146:7ffc9682b740: cnf:global:cfsysline: $FileOwner hadoop
7731.895912148:7ffc9682b740: uid 1208 obtained for user 'hadoop'
7731.895925220:7ffc9682b740: cnf:global:cfsysline: $FileGroup hadoop
7731.895988075:7ffc9682b740: gid 492 obtained for group 'hadoop'
7731.895998173:7ffc9682b740: cnf:global:cfsysline: $FileCreateMode 0640
7731.896007136:7ffc9682b740: cnf:global:cfsysline: $DirCreateMode 0755
7731.896014235:7ffc9682b740: cnf:global:cfsysline: $Umask 0022
7731.896022298:7ffc9682b740: cnf:global:cfsysline: $OMHDFSFileName /rsyslog_test/testchunsheng.rsyslog.v8.log
7731.896033112:7ffc9682b740: doGetWord: get newval '/rsyslog_test/testchunsheng.rsyslog.v8.log' (len 42), hdlr (nil)
7731.896039888:7ffc9682b740: cnf:global:cfsysline: $OMHDFSHost nn2.test.dip.sina.com.cn
7731.896048118:7ffc9682b740: doGetWord: get newval 'nn2.test.dip.sina.com.cn' (len 24), hdlr (nil)
7731.896054166:7ffc9682b740: cnf:global:cfsysline: $OMHDFSPort 8020
 */

/*
9710.846301576:7f5911d8e740: omhdfs:open file /rsyslog_test/testchunsheng.rsyslog.v8.log
9710.849931670:7f5911d8e740: omhdfs: hdfsExists return 0         name /rsyslog_test/testchunsheng.rsyslog.v8.log
9710.849948455:7f5911d8e740: omhdfs: HDFSFileExists return 1, file /rsyslog_test/testchunsheng.rsyslog.v8.log
9710.849962670:7f5911d8e740: omhdfs: error trying to create | append'/rsyslog_test/testchunsheng.rsyslog.v8.log',error 2,error msg No such file or directory
9710.849970020:7f5911d8e740: Called LogMsg, msg: omhdfs: failed to open /rsyslog_test/testchunsheng.rsyslog.v8.log - retrying later
 */

#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/file.h>
#include <pthread.h>
#include <libgen.h>
#ifdef HAVE_HDFS_H 
#include <hdfs.h>
#endif
#ifdef HAVE_HADOOP_HDFS_H 
#include <hadoop/hdfs.h>
#endif

#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "conf.h"
#include "cfsysline.h"
#include "module-template.h"
#include "unicode-helper.h"
#include "errmsg.h"
#include "hashtable.h"
#include "hashtable_itr.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
/* MODULE_CNFNAME("omhdfs") we need this only when we convert the module to v2 config system */

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)

/* global data */
static struct hashtable *files; /* holds all file objects that we know */
static pthread_mutex_t mutDoAct = PTHREAD_MUTEX_INITIALIZER;

typedef struct configSettings_s {
    uchar *fileName;
    uchar *hdfsHost;
    uchar *dfltTplName; /* default template name to use */
    //uchar *dynTplName; /*动态生成文件模板*/
    uchar *hdfsUser;
    int hdfsPort;
} configSettings_t;
static configSettings_t cs;

typedef struct {
    uchar *fileName;
    hdfsFS fs;
    hdfsFile fh;
    const uchar *hdfsHost;
    tPort hdfsPort;
    const uchar *hdfsUser;
    int nUsers;
    pthread_mutex_t mut;
} file_t;

typedef struct _instanceData {
    file_t *pFile;
    uchar ioBuf[ 8 * 8];
    unsigned offsBuf;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
} wrkrInstanceData_t;

/* forward definitions (down here, need data types) */
static inline rsRetVal fileClose(file_t *pFile);

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
if (eFeat == sFEATURERepeatedMsgReduction)
    iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
printf("omhdfs: file:%s host %s port %u", pData->pFile->fileName, pData->pFile->hdfsHost, pData->pFile->hdfsPort);

ENDdbgPrintInstInfo


/* note that hdfsFileExists() does not work, so we did our
 * own function to see if a pathname exists. Returns 0 if the
 * file does not exists, something else otherwise. Note that
 * we can also check a directroy (if that matters...)
 */
static int
HDFSFileExists(hdfsFS fs, char *name) {
    //	int r;
    //	hdfsFileInfo *info;
    //
    //	info = hdfsGetPathInfo(fs, (char*)name);
    //	/* if things go wrong, we assume it is because the file
    //	 * does not exist. We do not get too much information...
    //	 */
    //	if(info == NULL) {
    //		r = 0;
    //	} else {
    //		r = 1;
    //		hdfsFreeFileInfo(info, 1);
    //	}
    //	return r;
    int fileExist;
    fileExist = hdfsExists(fs, name);
    DBGPRINTF("omhdfs: hdfsExists return %d \t name %s\n", fileExist, name);
    if (fileExist >= -1) {
        return ++fileExist;
    } else {
        //TODO: 增加异常处理
        return -2;
    }
}

static inline rsRetVal
HDFSmkdir(hdfsFS fs, char *name) {
    DEFiRet;
    if (hdfsCreateDirectory(fs, name) == -1)
        ABORT_FINALIZE(RS_RET_ERR);

finalize_it:
    RETiRet;
}


/* ---BEGIN FILE OBJECT---------------------------------------------------- */

/* This code handles the "file object". This is split from the actual
 * instance data, because several instances may write into the same file.
 * If so, we need to use a single object, and also synchronize their writes.
 * So we keep the file object separately, and just stick a reference into
 * the instance data.
 */

static inline rsRetVal
fileObjConstruct(file_t **ppFile) {
    file_t *pFile;
    DEFiRet;

    CHKmalloc(pFile = malloc(sizeof (file_t)));
    pFile->fileName = NULL;
    pFile->hdfsHost = NULL;
    pFile->fh = NULL;
    pFile->hdfsUser = NULL;
    pFile->nUsers = 0;

    *ppFile = pFile;
finalize_it:
    RETiRet;
}

static inline void
fileObjAddUser(file_t *pFile) {
    /* init mutex only when second user is added */
    ++pFile->nUsers;
    if (pFile->nUsers >= 2)
        pthread_mutex_init(&pFile->mut, NULL);
    DBGPRINTF("omhdfs: file %s now being used by %d actions\n", pFile->fileName, pFile->nUsers);
}

static rsRetVal
fileObjDestruct(file_t **ppFile) {
    file_t *pFile = *ppFile;
    if (pFile->nUsers > 1)
        pthread_mutex_destroy(&pFile->mut);
    fileClose(pFile);
    free(pFile->fileName);
    free((char*) pFile->hdfsHost);
    free(pFile->fh);
    free((char *) pFile->hdfsUser);

    return RS_RET_OK;
}

/* check, and potentially create, all names inside a path */
static rsRetVal
dirPrepare(file_t *pFile) {
    //    uchar *p;
    //    uchar *pszWork;
    //    size_t len;
    DEFiRet;
    int re;
    //    int re = HDFSFileExists(pFile->fs, (char *)pFile->fileName);
    //    DBGPRINTF("omhdfs: HDFSFileExists return %d file : %s\n",re,(char *)pFile->fileName);
    //    if (re == 1)
    //        FINALIZE;
    char * filename_t = strdup((char*) pFile->fileName);
    char * dirname_t = dirname(filename_t);
    DBGPRINTF("omhdfs: dirname_t %s \n", dirname_t);

    re = HDFSFileExists(pFile->fs, dirname_t);
    DBGPRINTF("omhdfs: HDFSFileExists return %d file : %s \n", re, dirname_t);
    if (re == 1) {
        FINALIZE;
    } else {
        DBGPRINTF("omhdfs: try to mkdir %s \n", dirname_t);
        CHKiRet(HDFSmkdir(pFile->fs, dirname_t));
    }

    //    return 0;
    /* file does not exist, create it (and eventually parent directories */
    //    if (1) { // check if bCreateDirs
    //        len = ustrlen(pFile->fileName) + 1;
    //        CHKmalloc(pszWork = MALLOC(sizeof (uchar) * len));
    //        memcpy(pszWork, pFile->fileName, len);
    //        for (p = pszWork + 1; *p; p++)
    //            if (*p == '/') {
    //                /* temporarily terminate string, create dir and go on */
    //                *p = '\0';
    //                if (!HDFSFileExists(pFile->fs, pszWork)) {
    //                    CHKiRet(HDFSmkdir(pFile->fs, pszWork));
    //                }
    //                *p = '/';
    //            }
    //        free(pszWork);
    //        return 0;
    //    }


finalize_it:
    //    if(filename_t)
    free(filename_t);
    RETiRet;
}

/* this function is to be used as destructor for the
 * hash table code.
 */
static void
fileObjDestruct4Hashtable(void *ptr) {
    file_t *pFile = (file_t*) ptr;
    fileObjDestruct(&pFile);
}

static  rsRetVal
fileOpen(file_t *pFile) {
    DEFiRet;

    assert(pFile->fh == NULL);
    if (pFile->nUsers > 1)
        d_pthread_mutex_lock(&pFile->mut);

    DBGPRINTF("omhdfs: try to connect to HDFS at host '%s', port %d, user %s\n",
            pFile->hdfsHost, pFile->hdfsPort, pFile->hdfsUser);
    //pFile->fs = hdfsConnect(pFile->hdfsHost, pFile->hdfsPort);
    int i = 0;
    while (i < 3) {
        pFile->fs = hdfsConnectAsUser((char *) pFile->hdfsHost, pFile->hdfsPort, (char *) pFile->hdfsUser);
        if (pFile->fs == NULL) {
            i++;
            DBGPRINTF("omhdfs: connect hdfsServer %s faile, return errno: %d ,try again: %d\n", pFile->hdfsHost, errno, i)
            sleep(3);
        } else {
            i = 3 ;
        }
    }
    if (pFile->fs == NULL) {
        DBGPRINTF("omhdfs: error can not connect to hdfs errno %d msg: %s\n", errno, strerror(errno));
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    CHKiRet(dirPrepare(pFile));

    DBGPRINTF("omhdfs: %s", "done dirPrepare\n \t try to open file \n");
    DBGPRINTF("omhdfs:open file %s \n", (char*) pFile->fileName);
    int re;
    re = HDFSFileExists(pFile->fs, (char *) pFile->fileName);
    DBGPRINTF("omhdfs: HDFSFileExists return %d, file %s \n", re, (char *) pFile->fileName);
    i = 0 ;
    while (i < 3) {
        if (re) {
            pFile->fh = hdfsOpenFile(pFile->fs, (char*) pFile->fileName, O_WRONLY | O_APPEND, 3, 0, 1024);
            DBGPRINTF("omhdfs: hdfsOpenFile with flag: O_WRONLY | O_APPEND \n");
        } else {
            pFile->fh = hdfsOpenFile(pFile->fs, (char*) pFile->fileName, O_WRONLY | O_CREAT, 3, 0, 1024);
            DBGPRINTF("omhdfs: hdfsOpenFile with flag: O_WRONLY | O_CREAT \n");
            //TODO:hdfsOpenFile blocksize param 必须可以配置，并且必须是 hdfs 服务器配置中某个参数的倍数（稍后搞清楚）
            //java.io.IOException: io.bytes.per.checksum(512) and blockSize(1023) do not match. blockSize should be a multiple of io.bytes.per.checksum
        }
        if (pFile->fh == NULL) {
            i++;
            DBGPRINTF("omhdfs: hdfsOpenFile %s failed, return errno: %d ,try again: %d \n", pFile->fileName, errno, i)
            sleep(3);
        } else {
            i = 3 ;
        }
    }

    //    if (pFile->fh == NULL) {
    /* maybe the file does not exist, so we try to create it now.
     * Note that we can not use hdfsExists() because of a deficit in
     * it: https://issues.apache.org/jira/browse/HDFS-1154
     * As of my testing, libhdfs at least seems to return ENOENT if
     * the file does not exist.
     */
    //        if (errno == ENOENT) {
    //            DBGPRINTF("omhdfs: ENOENT trying to append to '%s', now trying create\n",
    //                    pFile->fileName);
    //        }
    //        DBGPRINTF("omhdfs: error trying to append | create to '%s',error %d,error msg %s, now trying create again\n", pFile->fileName, errno, strerror(errno));
    //        pFile->fh = hdfsOpenFile(pFile->fs,(char*) pFile->fileName, O_WRONLY | O_CREAT, 3, 0, 1024);
    //    }
    if (pFile->fh == NULL) {
        DBGPRINTF("omhdfs: error trying to create | append'%s',error %d,error msg %s\n", pFile->fileName, errno, strerror(errno));
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    } else {
        DBGPRINTF("omhdfs: successed to open %s for writing !\n", pFile->fileName);
//        char hello[] = "helloworld  \n";
//        re = hdfsWrite(pFile->fs, pFile->fh,(uchar*)hello, strlen((const char*) hello));
//        hdfsFlush(pFile->fs, pFile->fh);
//        DBGPRINTF("omhdfs: hdfsWrite hellowrod return %d",re);
        
        iRet = 0;
    }

finalize_it:
    if (pFile->nUsers > 1)
        d_pthread_mutex_unlock(&pFile->mut);
    RETiRet;
}

/* Note: lenWrite is reset to zero on successful write! */
static inline  rsRetVal
fileWrite(file_t *pFile, const uchar *buf, unsigned *lenWrite) {
    DEFiRet;

    DBGPRINTF("omhdfs: fileWrite param len(buf) %zu lenWrite %hu \n", strlen((const char *) buf), *lenWrite);

    if (*lenWrite == 0)
        FINALIZE;



    /* open file if not open. This must be done *here* and while mutex-protected
     * because of HUP handling (which is async to normal processing!).
     */
    if (pFile->fh == NULL) {
        fileOpen(pFile);
        if (pFile->fh == NULL) {
            ABORT_FINALIZE(RS_RET_SUSPENDED);
        }
    }


    //TODO: 此处需要重点进行 debug
    DBGPRINTF("XXXXX: omhdfs will writing %hu bytes\n", *lenWrite);

    if (pFile->nUsers > 1)
        d_pthread_mutex_lock(&pFile->mut);
    tSize num_written_bytes = hdfsWrite(pFile->fs, pFile->fh, buf, *lenWrite);
    if (pFile->nUsers > 1)
        d_pthread_mutex_unlock(&pFile->mut);
    if (num_written_bytes == -1) {
        DBGPRINTF("omhdfs: hdfsWrite failed error %d msg %s \n", errno, strerror(errno));
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    } else {
        DBGPRINTF("omhdfs: hdfsWrite succ,write %d bytes ,begin flush..\n", num_written_bytes);
        int re = hdfsFlush(pFile->fs, pFile->fh);
        DBGPRINTF("omhdfs: hdfsWrite flushing return %d..\n", re);
        //        fileClose(pFile);
        //        ABORT_FINALIZE(errno); /*for debuging*/
        //        exit(1);
    }

    if ((unsigned) num_written_bytes != *lenWrite) {
        errmsg.LogError(errno, RS_RET_ERR_HDFS_WRITE,
                "omhdfs: failed to write %s, expected %hu bytes, "
                "written %hu\n", pFile->fileName, *lenWrite,
                (unsigned) num_written_bytes);
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }
    *lenWrite = 0;

finalize_it:

    RETiRet;
}

static inline rsRetVal
fileClose(file_t *pFile) {
    DEFiRet;
    DBGPRINTF("omhdfs: fileClose \n");
    if (pFile->fh == NULL){
        DBGPRINTF("omhdfs: fileClose pFile->fh == NULL ,error occer \n");
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    if (pFile->nUsers > 1)
        d_pthread_mutex_lock(&pFile->mut);

    DBGPRINTF("omhdfs: fileClose try flush and close file");
    CHKiRet(hdfsFlush(pFile->fs, pFile->fh));
    CHKiRet(hdfsCloseFile(pFile->fs, pFile->fh));
    pFile->fh = NULL;

    if (pFile->nUsers > 1)
        d_pthread_mutex_unlock(&pFile->mut);

finalize_it:
    RETiRet;
}

/* ---END FILE OBJECT---------------------------------------------------- */

/* This adds data to the output buffer and performs an actual write
 * if the new data does not fit into the buffer. Note that we never write
 * partial data records. Other actions may write into the same file, and if
 * we would write partial records, data could become severely mixed up.
 * Note that we must check of some new data arrived is large than our
 * buffer. In that case, the new data will written with its own
 * write operation.
 */
static rsRetVal
addData(instanceData *pData, uchar *buf) {
    unsigned len;
    DEFiRet;

    len = strlen((char*) buf);
    DBGPRINTF("omhdfs: adddata param len %d buf %s \n", len, buf);

    DBGPRINTF("omhdfs: pData->offsBuf %d ,size_of(pData->ioBuf) %zu \n", pData->offsBuf, sizeof (pData->ioBuf));
    if (pData->offsBuf + len < sizeof (pData->ioBuf)) {
        /* new data fits into remaining buffer */
        memcpy((char*) pData->ioBuf + pData->offsBuf, buf, len);
        pData->offsBuf += len;
    } else {
        dbgprintf("XXXXX: not enough room, need to fileWrite\n");
        if (pData->offsBuf > 0) {
            CHKiRet(fileWrite(pData->pFile, pData->ioBuf, &pData->offsBuf));
        }
        if (len >= sizeof (pData->ioBuf)) {
            CHKiRet(fileWrite(pData->pFile, buf, &len));
        } else {
            memcpy((char*) pData->ioBuf + pData->offsBuf, buf, len);
            pData->offsBuf += len;
        }
    }

    iRet = RS_RET_DEFER_COMMIT;
finalize_it:
    RETiRet;
}

BEGINcreateInstance
CODESTARTcreateInstance
pData->pFile = NULL;
ENDcreateInstance


BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance


BEGINfreeInstance
CODESTARTfreeInstance
if (pData->pFile != NULL)
    fileObjDestruct(&pData->pFile);
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
//add by chunshengsterATgmail.com .this two lines are not sure!!
//if (pData->pFile != NULL)
//    fileObjDestruct(&pData->pFile);
ENDfreeWrkrInstance


BEGINtryResume
instanceData *pData = pWrkrData->pData;
CODESTARTtryResume
pthread_mutex_lock(&mutDoAct);
fileClose(pData->pFile);
fileOpen(pData->pFile);
if (pData->pFile->fh == NULL) {
    dbgprintf("omhdfs: tried to resume file %s, but still no luck...\n",
            pData->pFile->fileName);
    iRet = RS_RET_SUSPENDED;
}
pthread_mutex_unlock(&mutDoAct);
ENDtryResume


//this time not support transction
BEGINbeginTransaction
CODESTARTbeginTransaction
dbgprintf("omhdfs: beginTransaction, but no code support this time \n");
ENDbeginTransaction


BEGINdoAction
instanceData *pData = pWrkrData->pData;
CODESTARTdoAction
DBGPRINTF("omhdfs: action to to write to %s\n", pData->pFile->fileName);
pthread_mutex_lock(&mutDoAct);
DBGPRINTF("omhdfs: action to write string %s \n", ppString[0]);
iRet = addData(pData, ppString[0]);
DBGPRINTF("omhdfs: done doAction\n");
pthread_mutex_unlock(&mutDoAct);
ENDdoAction


BEGINendTransaction
instanceData *pData = pWrkrData->pData;
CODESTARTendTransaction
//iRet = addData(pData, ppString[0]);
pthread_mutex_lock(&mutDoAct);
if (pData->offsBuf != 0) {
    DBGPRINTF("omhdfs: data unwritten at end of transaction, persisting...\n");
    iRet = fileWrite(pData->pFile, pData->ioBuf, &pData->offsBuf);
}
pthread_mutex_unlock(&mutDoAct);
dbgprintf("omhdfs: endTransaction\n");
ENDendTransaction


BEGINparseSelectorAct
file_t *pFile;
int r;
uchar *keybuf;
CODESTARTparseSelectorAct

        /* first check if this config line is actually for us */
if (strncmp((char*) p, ":omhdfs:", sizeof (":omhdfs:") - 1)) {
    ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
}

/* ok, if we reach this point, we have something for us */
p += sizeof (":omhdfs:") - 1; /* eat indicator sequence  (-1 because of '\0'!) */
CHKiRet(createInstance(&pData));
CODE_STD_STRING_REQUESTparseSelectorAct(1)
CHKiRet(cflineParseTemplateName(&p, *ppOMSR, 0, 0,
        (cs.dfltTplName == NULL) ? (uchar*) "RSYSLOG_FileFormat" : cs.dfltTplName));

if (cs.fileName == NULL) {
    errmsg.LogError(0, RS_RET_ERR_HDFS_OPEN, "omhdfs: no file name specified, can not continue");
    ABORT_FINALIZE(RS_RET_FILE_NOT_SPECIFIED);
}

pFile = hashtable_search(files, cs.fileName);
if (pFile == NULL) {
    /* we need a new file object, this one not seen before */
    CHKiRet(fileObjConstruct(&pFile));
    CHKmalloc(pFile->fileName = cs.fileName);
    CHKmalloc(keybuf = ustrdup(cs.fileName));
    /* add hdfsUser param*/
    if (cs.hdfsUser == NULL) {
        // TODO: find hadoop user in system,if exists, use is,else exit and say error
        cs.hdfsUser = (uchar*) "hadoop";
    }
    CHKmalloc(pFile->hdfsUser = (char*) cs.hdfsUser);
    cs.fileName = NULL; /* re-set, data passed to file object */
    CHKmalloc(pFile->hdfsHost = strdup((cs.hdfsHost == NULL) ? "default" : (char*) cs.hdfsHost));
    pFile->hdfsPort = cs.hdfsPort;
    fileOpen(pFile);
    if (pFile->fh == NULL) {
        errmsg.LogError(0, RS_RET_ERR_HDFS_OPEN, "omhdfs: failed to open %s - "
                "retrying later", pFile->fileName);
        iRet = RS_RET_SUSPENDED;
    }
    r = hashtable_insert(files, keybuf, pFile);
    if (r == 0)
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
}

fileObjAddUser(pFile);
pData->pFile = pFile;
pData->offsBuf = 0;

CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINdoHUP
file_t *pFile;
struct hashtable_itr *itr;
CODESTARTdoHUP
DBGPRINTF("omhdfs: HUP received (file count %d)\n", hashtable_count(files));
/* Iterator constructor only returns a valid iterator if
 * the hashtable is not empty */
itr = hashtable_iterator(files);
if (hashtable_count(files) > 0) {
    do {
        pFile = (file_t *) hashtable_iterator_value(itr);
        fileClose(pFile);
        DBGPRINTF("omhdfs: HUP, closing file %s\n", pFile->fileName);
    } while (hashtable_iterator_advance(itr));
}

ENDdoHUP


/* Reset config variables for this module to default values.
 * rgerhards, 2007-07-17
 */
static rsRetVal resetConfigVariables(uchar __attribute__((unused)) * pp, void __attribute__((unused)) * pVal) {
    cs.hdfsHost = NULL;
    cs.hdfsPort = 0;
    free(cs.fileName);
    cs.fileName = NULL;
    free(cs.dfltTplName);
    cs.dfltTplName = NULL;
    cs.hdfsUser = NULL;
    return RS_RET_OK;
}


BEGINmodExit
CODESTARTmodExit
objRelease(errmsg, CORE_COMPONENT);
if (files != NULL)
    hashtable_destroy(files, 1); /* 1 => free all values automatically */
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_TXIF_OMOD_QUERIES /* we support the transactional interface! */
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_doHUP
ENDqueryEtryPt



BEGINmodInit()
CODESTARTmodInit
*ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
CHKiRet(objUse(errmsg, CORE_COMPONENT));
CHKmalloc(files = create_hashtable(20, hash_from_string, key_equals_string,
        fileObjDestruct4Hashtable));

CHKiRet(regCfSysLineHdlr((uchar *) "omhdfsfilename", 0, eCmdHdlrGetWord, NULL, &cs.fileName, NULL));
CHKiRet(regCfSysLineHdlr((uchar *) "omhdfshost", 0, eCmdHdlrGetWord, NULL, &cs.hdfsHost, NULL));
CHKiRet(regCfSysLineHdlr((uchar *) "omhdfsport", 0, eCmdHdlrInt, NULL, &cs.hdfsPort, NULL));
CHKiRet(regCfSysLineHdlr((uchar *) "omhdfsdefaulttemplate", 0, eCmdHdlrGetWord, NULL, &cs.dfltTplName, NULL));
CHKiRet(regCfSysLineHdlr((uchar *) "omhdfsuser", 0, eCmdHdlrGetWord, NULL, &cs.hdfsUser, NULL));
CHKiRet(omsdRegCFSLineHdlr((uchar *) "resetconfigvariables", 1, eCmdHdlrCustomHandler, resetConfigVariables, NULL, STD_LOADABLE_MODULE_ID));
DBGPRINTF("omhdfs: module compiled with rsyslog version %s.\n", VERSION);
CODEmodInit_QueryRegCFSLineHdlr
ENDmodInit
