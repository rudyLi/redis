/* zmalloc - total amount of allocated memory aware version of malloc()
 *
 * Copyright (c) 2009-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>

/* This function provide us access to the original libc free(). This is useful
 * for instance to free results obtained by backtrace_symbols(). We need
 * to define this function before including zmalloc.h that may shadow the
 * free implementation if we use jemalloc or another non standard allocator. */
/* 调用libc中free方法，以防include zmalloc.h 覆盖方法 */
void zlibc_free(void *ptr) {
    free(ptr);
}

#include <string.h>
#include <pthread.h>
#include "config.h"
#include "zmalloc.h"

#ifdef HAVE_MALLOC_SIZE
#define PREFIX_SIZE (0)
#else
/*sun 操作系统 longl long类型长度*/
#if defined(__sun) || defined(__sparc) || defined(__sparc__)
#define PREFIX_SIZE (sizeof(long long))
#else
#define PREFIX_SIZE (sizeof(size_t))
#endif
#endif

/* Explicitly override malloc/free etc when using tcmalloc. */
/*可以使用goole的thread_cache molloc 库或者 jemalloc*/
#if defined(USE_TCMALLOC)
#define malloc(size) tc_malloc(size)
#define calloc(count,size) tc_calloc(count,size)
#define realloc(ptr,size) tc_realloc(ptr,size)
#define free(ptr) tc_free(ptr)
#elif defined(USE_JEMALLOC)
#define malloc(size) je_malloc(size)
#define calloc(count,size) je_calloc(count,size)
#define realloc(ptr,size) je_realloc(ptr,size)
#define free(ptr) je_free(ptr)
#endif

#ifdef HAVE_ATOMIC
#define update_zmalloc_stat_add(__n) __sync_add_and_fetch(&used_memory, (__n))
#define update_zmalloc_stat_sub(__n) __sync_sub_and_fetch(&used_memory, (__n))
#else
/* 统一保存内存大小状态，add为增加，sub为free时调用，是线程安全的*/
#define update_zmalloc_stat_add(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory += (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)

#define update_zmalloc_stat_sub(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory -= (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)

#endif
/*amalloc调用完后，更新内存大小记录*/
#define update_zmalloc_stat_alloc(__n) do { \
    size_t _n = (__n); \
	/*alloc分配内存大小是sizeof long 大小的倍数，即 sizeof（long）字节对其，增加cpu访问速度，在32位 long 4。64位 8字节 */
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \
	  /*在redis操作中会出现多线程运行，所以对内存使用大小记录要线程安全*/
    if (zmalloc_thread_safe) { \
        update_zmalloc_stat_add(_n); \
    } else { \
        used_memory += _n; \
    } \
} while(0)
/*释放内存时更新使用内存大小记录*/
#define update_zmalloc_stat_free(__n) do { \
    size_t _n = (__n); \
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \
    if (zmalloc_thread_safe) { \
        update_zmalloc_stat_sub(_n); \
    } else { \
        used_memory -= _n; \
    } \
} while(0)

static size_t used_memory = 0;
static int zmalloc_thread_safe = 0;
pthread_mutex_t used_memory_mutex = PTHREAD_MUTEX_INITIALIZER;

/*out of memory 异常处理函数*/
static void zmalloc_default_oom(size_t size) {
    fprintf(stderr, "zmalloc: Out of memory trying to allocate %zu bytes\n",
        size);
	/*冲洗内存空间，刷出到指定fd上,发送abort信号*/
    fflush(stderr);
    abort();
}

/*oom默认异常处理函数*/
static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;

/*malloc 的封装，不同的是另外开辟一快空间记录分配内存的大小*/
void *zmalloc(size_t size) {
    void *ptr = malloc(size+PREFIX_SIZE);

    if (!ptr) zmalloc_oom_handler(size);
	/*如果ptr地址包括mallocsize，则使用zmalloc_size方法获得内存大小*/
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
	/*返回数据真正开始的地址*/
    return (char*)ptr+PREFIX_SIZE;
#endif
}
/*封装calloc方法*/
void *zcalloc(size_t size) {
    void *ptr = calloc(1, size+PREFIX_SIZE);

    if (!ptr) zmalloc_oom_handler(size);
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;
#endif
}

void *zrealloc(void *ptr, size_t size) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
#endif
    size_t oldsize;
    void *newptr;

    if (ptr == NULL) return zmalloc(size);
#ifdef HAVE_MALLOC_SIZE
    oldsize = zmalloc_size(ptr);
    newptr = realloc(ptr,size);
    if (!newptr) zmalloc_oom_handler(size);

    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(zmalloc_size(newptr));
    return newptr;
#else
	/*先获得真正内存区域的起始地址，取出内存区域大小，调用realloc分配内存*/
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    newptr = realloc(realptr,size+PREFIX_SIZE);
    if (!newptr) zmalloc_oom_handler(size);

    *((size_t*)newptr) = size;
	/*更新内存状态，先减小free的内存大小，再增加重新分配区域的大小*/
    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(size);
    return (char*)newptr+PREFIX_SIZE;
#endif
}

/* Provide zmalloc_size() for systems where this function is not provided by
 * malloc itself, given that in that case we store an header with this
 * information as the first bytes of every allocation. */
#ifndef HAVE_MALLOC_SIZE
size_t zmalloc_size(void *ptr) {
    void *realptr = (char*)ptr-PREFIX_SIZE;
    size_t size = *((size_t*)realptr);
    /* Assume at least that all the allocations are padded at sizeof(long) by
     * the underlying allocator. */
    if (size&(sizeof(long)-1)) size += sizeof(long)-(size&(sizeof(long)-1));
    return size+PREFIX_SIZE;
}
#endif

void zfree(void *ptr) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
    size_t oldsize;
#endif

    if (ptr == NULL) return;
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_free(zmalloc_size(ptr));
    free(ptr);
#else
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    update_zmalloc_stat_free(oldsize+PREFIX_SIZE);
    free(realptr);
#endif
}
/*字符串复制*/
char *zstrdup(const char *s) {
	/*还有末尾的0*/
    size_t l = strlen(s)+1;
    char *p = zmalloc(l);

    memcpy(p,s,l);
    return p;
}
/*查询使用内存大小*/
size_t zmalloc_used_memory(void) {
    size_t um;

    if (zmalloc_thread_safe) {
#ifdef HAVE_ATOMIC
        um = __sync_add_and_fetch(&used_memory, 0);
#else
        pthread_mutex_lock(&used_memory_mutex);
        um = used_memory;
        pthread_mutex_unlock(&used_memory_mutex);
#endif
    }
    else {
        um = used_memory;
    }

    return um;
}

/*设置线程安全标志函数*/
void zmalloc_enable_thread_safeness(void) {
    zmalloc_thread_safe = 1;
}
/*自定义oom处理函数*/
void zmalloc_set_oom_handler(void (*oom_handler)(size_t)) {
    zmalloc_oom_handler = oom_handler;
}

/* Get the RSS information in an OS-specific way.
 *
 * WARNING: the function zmalloc_get_rss() is not designed to be fast
 * and may not be called in the busy loops where Redis tries to release
 * memory expiring or swapping out objects.
 *
 * For this kind of "fast RSS reporting" usages use instead the
 * function RedisEstimateRSS() that is a much faster (and less precise)
 * version of the function. */

#if defined(HAVE_PROC_STAT)
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/*此方法并不会快速返回rss resident set size 使用内存大小*/
size_t zmalloc_get_rss(void) {
	/*读取配置文件，查看page大小，因为redis自己有设置虚拟内存，操作系统的虚拟内存4k太大*/
    int page = sysconf(_SC_PAGESIZE);
    size_t rss;
    char buf[4096];
    char filename[256];
    int fd, count;
    char *p, *x;
/*获得文件名/proc/pid/stat 记录每个进程的状态信息，proc/目录下的文件并没有写到硬盘中，状态为只读，此目录下记载着内涵返回用户的具体信息*/
    snprintf(filename,256,"/proc/%d/stat",getpid());
    if ((fd = open(filename,O_RDONLY)) == -1) return 0;
    if (read(fd,buf,4096) <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    p = buf;
    count = 23; /* RSS is the 24th field in /proc/<pid>/stat */
    while(p && count--) {
		/*找到一个 ‘ ’ 的位置*/
        p = strchr(p,' ');
        if (p) p++;
    }
    if (!p) return 0;
    x = strchr(p,' ');
    if (!x) return 0;
    *x = '\0';
    /*字符串转为10进制数*/
    rss = strtoll(p,NULL,10);
	/*乘以没页大小*/
    rss *= page;
    return rss;
}
#elif defined(HAVE_TASKINFO)
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/task.h>
#include <mach/mach_init.h>

size_t zmalloc_get_rss(void) {
    task_t task = MACH_PORT_NULL;
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (task_for_pid(current_task(), getpid(), &task) != KERN_SUCCESS)
        return 0;
    task_info(task, TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count);

    return t_info.resident_size;
}
#else
size_t zmalloc_get_rss(void) {
    /* If we can't get the RSS in an OS-specific way for this system just
     * return the memory usage we estimated in zmalloc()..
     *
     * Fragmentation will appear to be always 1 (no fragmentation)
     * of course... */
    return zmalloc_used_memory();
}
#endif

/* Fragmentation = RSS / allocated-bytes */
/*碎片率，rss除以内存使用记录*/
float zmalloc_get_fragmentation_ratio(void) {
    return (float)zmalloc_get_rss()/zmalloc_used_memory();
}

#if defined(HAVE_PROC_SMAPS)
/*需要swap和写入到硬盘的那部分区域为dirty，可以理解为内存中这部分有写操作*/
size_t zmalloc_get_private_dirty(void) {
    char line[1024];
    size_t pd = 0;
    FILE *fp = fopen("/proc/self/smaps","r");

    if (!fp) return 0;
    while(fgets(line,sizeof(line),fp) != NULL) {
        if (strncmp(line,"Private_Dirty:",14) == 0) {
            char *p = strchr(line,'k');
            if (p) {
                *p = '\0';
                pd += strtol(line+14,NULL,10) * 1024;
            }
        }
    }
    fclose(fp);
    return pd;
}
#else
size_t zmalloc_get_private_dirty(void) {
    return 0;
}
#endif
