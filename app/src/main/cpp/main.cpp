#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <map>
#include <cstdio>
#include <cstring>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "zygisk.hpp"
#include "json/single_include/nlohmann/json.hpp"
#include "dobby.h"

// 兼容性兜底：解决部分 NDK 版本未声明 memfd_create 的问题
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static inline int compat_memfd_create(const char *name, unsigned int flags) {
    return static_cast<int>(syscall(__NR_memfd_create, name, flags));
}
#define memfd_create compat_memfd_create

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "TFIX/Native", __VA_ARGS__)
#define DEX_FILE_PATH "/data/adb/modules/targetedfix/classes.dex"

// 硬编码伪装参数：32GB 总存储空间
static constexpr uint64_t FAKE_TOTAL_GB = 32; 

static bool spoofStorage = (FAKE_TOTAL_GB > 0);
static const uint64_t FAKE_BLOCK_SIZE = 4096;
static fsblkcnt_t fakeTotalBlocks = (FAKE_TOTAL_GB * 1024ULL * 1024ULL * 1024ULL) / FAKE_BLOCK_SIZE;

// ==================== 内存 (RAM) 伪装参数配置 ====================
static constexpr uint64_t FAKE_RAM_TOTAL_GB = 4ULL; // 总 RAM 固定为 4GB
static constexpr uint64_t FAKE_RAM_TOTAL_KB = FAKE_RAM_TOTAL_GB * 1024ULL * 1024ULL; // 4194304 kB
static constexpr uint64_t FAKE_RAM_TOTAL_BYTES = FAKE_RAM_TOTAL_GB * 1024ULL * 1024ULL * 1024ULL;

typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);
static std::map<void *, T_Callback> callbacks;

static void modify_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (cookie == nullptr || name == nullptr || value == nullptr || !callbacks.contains(cookie)) return;
    return callbacks[cookie](cookie, name, value, serial);
}

static void (*o_system_property_read_callback)(const prop_info *, T_Callback, void *);

static void my_system_property_read_callback(const prop_info *pi, T_Callback callback, void *cookie) {
    if (pi == nullptr || callback == nullptr || cookie == nullptr) {
        return o_system_property_read_callback(pi, callback, cookie);
    }
    callbacks[cookie] = callback;
    return o_system_property_read_callback(pi, modify_callback, cookie);
}

// ==================== statvfs / statfs 存储 Hook 逻辑 ====================
static int (*orig_statvfs)(const char *path, struct statvfs *buf) = nullptr;
static int (*orig_statfs)(const char *path, struct statfs *buf) = nullptr;

static inline bool is_user_storage_path(const char *path) {
    if (!path) return false;
    return (strncmp(path, "/data", 5) == 0 || 
            strncmp(path, "/storage", 8) == 0 || 
            strncmp(path, "/sdcard", 7) == 0 ||
            strncmp(path, "/mnt", 4) == 0 ||
            strcmp(path, "/") == 0);
}

static int my_statvfs(const char *path, struct statvfs *buf) {
    int result = orig_statvfs(path, buf);
    if (result == 0 && buf != nullptr && spoofStorage && is_user_storage_path(path)) {
        uint64_t realFreeBlocks = buf->f_bfree;
        uint64_t fakeFreeBlocks = realFreeBlocks * 6ULL;
        
        if (fakeFreeBlocks > fakeTotalBlocks) {
            fakeFreeBlocks = fakeTotalBlocks;
        }

        buf->f_bsize   = FAKE_BLOCK_SIZE;
        buf->f_frsize  = FAKE_BLOCK_SIZE;
        buf->f_blocks  = fakeTotalBlocks;
        buf->f_bfree   = static_cast<fsblkcnt_t>(fakeFreeBlocks);
        buf->f_bavail  = static_cast<fsblkcnt_t>(fakeFreeBlocks);
    }
    return result;
}

static int my_statfs(const char *path, struct statfs *buf) {
    int result = orig_statfs(path, buf);
    if (result == 0 && buf != nullptr && spoofStorage && is_user_storage_path(path)) {
        uint64_t realFreeBlocks = buf->f_bfree;
        uint64_t fakeFreeBlocks = realFreeBlocks * 6ULL;

        if (fakeFreeBlocks > fakeTotalBlocks) {
            fakeFreeBlocks = fakeTotalBlocks;
        }

        buf->f_bsize  = FAKE_BLOCK_SIZE;
        buf->f_blocks = fakeTotalBlocks;
        buf->f_bfree  = static_cast<fsblkcnt_t>(fakeFreeBlocks);
        buf->f_bavail = static_cast<fsblkcnt_t>(fakeFreeBlocks);
    }
    return result;
}

// ==================== RAM 内存 Hook 核心逻辑 ====================

// 1. sysinfo API Hook
static int (*orig_sysinfo)(struct sysinfo *info) = nullptr;

static int my_sysinfo(struct sysinfo *info) {
    int res = orig_sysinfo(info);
    if (res == 0 && info != nullptr) {
        uint64_t unit = info->mem_unit ? info->mem_unit : 1;
        
        unsigned long long real_total = info->totalram * unit;
        unsigned long long real_free = info->freeram * unit;
        unsigned long long real_used = (real_total > real_free) ? (real_total - real_free) : real_free;
        
        unsigned long long fake_used = real_used * 2ULL;
        unsigned long long fake_total = FAKE_RAM_TOTAL_BYTES;
        if (fake_used >= fake_total) fake_used = fake_total - (512ULL * 1024ULL * 1024ULL);
        unsigned long long fake_free = fake_total - fake_used;

        info->totalram  = static_cast<unsigned long>(fake_total / unit);
        info->freeram   = static_cast<unsigned long>(fake_free / unit);
        info->bufferram = static_cast<unsigned long>((info->bufferram * 2ULL));
    }
    return res;
}

// 2. /proc/meminfo 文件 Hook
static std::string generate_fake_meminfo() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return "";

    char line[256];
    std::map<std::string, unsigned long long> memMap;

    while (fgets(line, sizeof(line), fp)) {
        char key[64] = {0};
        unsigned long long val = 0;
        if (sscanf(line, "%63s %20llu", key, &val) == 2) {
            size_t len = strlen(key);
            if (len > 0 && key[len - 1] == ':') {
                key[len - 1] = '\0';
            }
            memMap[key] = val;
        }
    }
    fclose(fp);

    unsigned long long r_total = memMap.count("MemTotal") ? memMap["MemTotal"] : 2055168ULL;
    unsigned long long r_free = memMap.count("MemFree") ? memMap["MemFree"] : 494076ULL;
    unsigned long long r_avail = memMap.count("MemAvailable") ? memMap["MemAvailable"] : 1087320ULL;
    unsigned long long r_buffers = memMap.count("Buffers") ? memMap["Buffers"] : 7676ULL;
    unsigned long long r_cached = memMap.count("Cached") ? memMap["Cached"] : 718756ULL;

    unsigned long long r_used = (r_total > r_avail) ? (r_total - r_avail) : (r_total - r_free);
    unsigned long long f_used = r_used * 2ULL;
    unsigned long long f_total = FAKE_RAM_TOTAL_KB;

    if (f_used >= f_total) {
        f_used = f_total - 512ULL * 1024ULL;
    }

    unsigned long long f_avail = f_total - f_used;
    double scale = (r_avail > 0) ? ((double)f_avail / (double)r_avail) : 1.0;
    
    unsigned long long f_free = (unsigned long long)(r_free * scale);
    unsigned long long f_buffers = (unsigned long long)(r_buffers * scale);
    unsigned long long f_cached = (unsigned long long)(r_cached * scale);

    fp = fopen("/proc/meminfo", "r");
    if (!fp) return "";

    std::string newContent;
    newContent.reserve(4096);

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "MemTotal:       %8llu kB\n", f_total);
            newContent += buf;
        } 
        else if (strncmp(line, "MemFree:", 8) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "MemFree:        %8llu kB\n", f_free);
            newContent += buf;
        } 
        else if (strncmp(line, "MemAvailable:", 13) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "MemAvailable:   %8llu kB\n", f_avail);
            newContent += buf;
        } 
        else if (strncmp(line, "Buffers:", 8) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Buffers:        %8llu kB\n", f_buffers);
            newContent += buf;
        } 
        else if (strncmp(line, "Cached:", 7) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Cached:         %8llu kB\n", f_cached);
            newContent += buf;
        } 
        else {
            newContent += line;
        }
    }
    fclose(fp);
    return newContent;
}

static int create_fake_meminfo_fd() {
    std::string fakeData = generate_fake_meminfo();
    if (fakeData.empty()) return -1;

    int memfd = memfd_create("meminfo", MFD_CLOEXEC);
    if (memfd < 0) return -1;

    write(memfd, fakeData.c_str(), fakeData.size());
    lseek(memfd, 0, SEEK_SET);
    return memfd;
}

static int (*orig_openat)(int dirfd, const char *pathname, int flags, mode_t mode) = nullptr;
static int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (pathname != nullptr && strcmp(pathname, "/proc/meminfo") == 0) {
        int fake_fd = create_fake_meminfo_fd();
        if (fake_fd >= 0) return fake_fd;
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

static int (*orig_open)(const char *pathname, int flags, mode_t mode) = nullptr;
static int my_open(const char *pathname, int flags, mode_t mode) {
    if (pathname != nullptr && strcmp(pathname, "/proc/meminfo") == 0) {
        int fake_fd = create_fake_meminfo_fd();
        if (fake_fd >= 0) return fake_fd;
    }
    return orig_open(pathname, flags, mode);
}

static void doHook() {
    void *handle = DobbySymbolResolver(nullptr, "__system_property_read_callback");
    if (handle != nullptr) {
        DobbyHook(handle, reinterpret_cast<dobby_dummy_func_t>(my_system_property_read_callback),
                  reinterpret_cast<dobby_dummy_func_t *>(&o_system_property_read_callback));
    }

    if (spoofStorage) {
        void* statvfs_ptr = DobbySymbolResolver(nullptr, "statvfs");
        if (!statvfs_ptr) statvfs_ptr = DobbySymbolResolver(nullptr, "statvfs64");
        if (statvfs_ptr) {
            DobbyHook(statvfs_ptr, reinterpret_cast<dobby_dummy_func_t>(my_statvfs),
                      reinterpret_cast<dobby_dummy_func_t*>(&orig_statvfs));
        }

        void* statfs_ptr = DobbySymbolResolver(nullptr, "statfs");
        if (!statfs_ptr) statfs_ptr = DobbySymbolResolver(nullptr, "statfs64");
        if (statfs_ptr) {
            DobbyHook(statfs_ptr, reinterpret_cast<dobby_dummy_func_t>(my_statfs),
                      reinterpret_cast<dobby_dummy_func_t*>(&orig_statfs));
        }
    }

    void* sysinfo_ptr = DobbySymbolResolver(nullptr, "sysinfo");
    if (sysinfo_ptr) {
        DobbyHook(sysinfo_ptr, reinterpret_cast<dobby_dummy_func_t>(my_sysinfo),
                  reinterpret_cast<dobby_dummy_func_t*>(&orig_sysinfo));
    }

    void* openat_ptr = DobbySymbolResolver(nullptr, "openat");
    if (openat_ptr) {
        DobbyHook(openat_ptr, reinterpret_cast<dobby_dummy_func_t>(my_openat),
                  reinterpret_cast<dobby_dummy_func_t*>(&orig_openat));
    }

    void* open_ptr = DobbySymbolResolver(nullptr, "open");
    if (open_ptr) {
        DobbyHook(open_ptr, reinterpret_cast<dobby_dummy_func_t>(my_open),
                  reinterpret_cast<dobby_dummy_func_t*>(&orig_open));
    }
}

static void setFieldNative(JNIEnv *env, jclass, jclass targetClass, jobject fieldObj, jstring typeObj, jobject valueObj) {
    if (!targetClass || !fieldObj || !typeObj) return;

    jfieldID fieldID = env->FromReflectedField(fieldObj);
    if (!fieldID) return;

    const char *typeName = env->GetStringUTFChars(typeObj, nullptr);

    if (strcmp(typeName, "java.lang.String") == 0) {
        env->SetStaticObjectField(targetClass, fieldID, valueObj);
    } else if (strcmp(typeName, "int") == 0) {
        jclass intClass = env->FindClass("java/lang/Integer");
        jmethodID intValue = env->GetMethodID(intClass, "intValue", "()I");
        env->SetStaticIntField(targetClass, fieldID, env->CallIntMethod(valueObj, intValue));
    } else if (strcmp(typeName, "long") == 0) {
        jclass longClass = env->FindClass("java/lang/Long");
        jmethodID longValue = env->GetMethodID(longClass, "longValue", "()J");
        env->SetStaticLongField(targetClass, fieldID, env->CallLongMethod(valueObj, longValue));
    } else if (strcmp(typeName, "boolean") == 0) {
        jclass boolClass = env->FindClass("java/lang/Boolean");
        jmethodID booleanValue = env->GetMethodID(boolClass, "booleanValue", "()Z");
        env->SetStaticBooleanField(targetClass, fieldID, env->CallBooleanMethod(valueObj, booleanValue));
    } else if (strcmp(typeName, "[Ljava.lang.String;") == 0) {
        env->SetStaticObjectField(targetClass, fieldID, valueObj);
    }

    env->ReleaseStringUTFChars(typeObj, typeName);
}

class TargetedFix : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (args == nullptr || args->app_data_dir == nullptr || args->nice_name == nullptr) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto rawProcess = env->GetStringUTFChars(args->nice_name, nullptr);
        auto rawDir = env->GetStringUTFChars(args->app_data_dir, nullptr);

        if (rawDir == nullptr || rawProcess == nullptr) {
            if (rawProcess) env->ReleaseStringUTFChars(args->nice_name, rawProcess);
            if (rawDir) env->ReleaseStringUTFChars(args->app_data_dir, rawDir);
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        std::string processStr(rawProcess);

        env->ReleaseStringUTFChars(args->nice_name, rawProcess);
        env->ReleaseStringUTFChars(args->app_data_dir, rawDir);

        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

        long dexSize = 0;
        int fd = api->connectCompanion();

        long processSize = processStr.size();
        write(fd, &processSize, sizeof(long));
        write(fd, processStr.data(), processSize);

        read(fd, &dexSize, sizeof(long));

        if (dexSize < 1) {
            close(fd);
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        dexVector.resize(dexSize);
        read(fd, dexVector.data(), dexSize);
        close(fd);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (dexVector.empty()) return;

        doHook();
        inject();

        dexVector.clear();
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        doHook();
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::vector<char> dexVector;

    void inject() {
        auto clClass = env->FindClass("java/lang/ClassLoader");
        auto getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        auto systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);

        auto dexClClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        auto dexClInit = env->GetMethodID(dexClClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        auto buffer = env->NewDirectByteBuffer(dexVector.data(), static_cast<jlong>(dexVector.size()));
        auto dexCl = env->NewObject(dexClClass, dexClInit, buffer, systemClassLoader);

        auto loadClass = env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");        
        const char* className = "es.chiteroman.playintegrityfix.EntryPoint";
        auto entryClassName = env->NewStringUTF(className);
        auto entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);

        auto entryClass = (jclass) entryClassObj;

        JNINativeMethod methods[] = {
            {"setFieldNative", "(Ljava/lang/Class;Ljava/lang/reflect/Field;Ljava/lang/String;Ljava/lang/Object;)V", (void*) setFieldNative}
        };
        env->RegisterNatives(entryClass, methods, 1);

        auto entryInit = env->GetStaticMethodID(entryClass, "init", "(IIII)V");
        env->CallStaticVoidMethod(entryClass, entryInit, 0, 1, 0, 0);

        env->DeleteLocalRef(clClass);
        env->DeleteLocalRef(dexClClass);
        env->DeleteLocalRef(systemClassLoader);
        env->DeleteLocalRef(dexCl);
        env->DeleteLocalRef(buffer);
        env->DeleteLocalRef(entryClassName);
        env->DeleteLocalRef(entryClassObj);
    }
};

static void companion(int fd) {
    long dexSize = 0;
    std::vector<char> dexVector;

    long processSize = 0;
    read(fd, &processSize, sizeof(long));
    std::string processName;
    processName.resize(processSize);
    read(fd, processName.data(), processSize);

    FILE *dex = fopen(DEX_FILE_PATH, "rb");
    if (dex) {
        fseek(dex, 0, SEEK_END);
        dexSize = ftell(dex);
        fseek(dex, 0, SEEK_SET);

        dexVector.resize(dexSize);
        fread(dexVector.data(), 1, dexSize, dex);
        fclose(dex);
    }

    write(fd, &dexSize, sizeof(long));
    write(fd, dexVector.data(), dexSize);
}

REGISTER_ZYGISK_MODULE(TargetedFix)
REGISTER_ZYGISK_COMPANION(companion)
