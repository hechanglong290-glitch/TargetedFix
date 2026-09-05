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

#include "zygisk.hpp"
#include "json/single_include/nlohmann/json.hpp"
#include "dobby.h"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "TFIX/Native", __VA_ARGS__)
#define DEX_FILE_PATH "/data/adb/modules/targetedfix/classes.dex"

// 硬编码伪装参数：32GB 总存储空间
static constexpr uint64_t FAKE_TOTAL_GB = 32; 

static bool spoofStorage = (FAKE_TOTAL_GB > 0);
static const uint64_t FAKE_BLOCK_SIZE = 4096;
static fsblkcnt_t fakeTotalBlocks = (FAKE_TOTAL_GB * 1024ULL * 1024ULL * 1024ULL) / FAKE_BLOCK_SIZE;

// ==================== 内存 (RAM) 伪装参数配置 ====================
static constexpr uint64_t FAKE_RAM_TOTAL_GB = 4ULL; // 总 RAM 改为 4GB
static constexpr uint64_t RAM_MULTIPLIER = 2ULL;     // 可用内存放大 2 倍
static constexpr uint64_t FAKE_RAM_TOTAL_KB = FAKE_RAM_TOTAL_GB * 1024ULL * 1024ULL;
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
        
        // 放大可用物理内存 (freeram)
        uint64_t realFreeBytes = static_cast<uint64_t>(info->freeram) * unit;
        uint64_t fakeFreeBytes = realFreeBytes * RAM_MULTIPLIER;
        if (fakeFreeBytes > FAKE_RAM_TOTAL_BYTES) {
            fakeFreeBytes = FAKE_RAM_TOTAL_BYTES;
        }

        // 放大缓冲内存 (bufferram)
        uint64_t realBufferBytes = static_cast<uint64_t>(info->bufferram) * unit;
        uint64_t fakeBufferBytes = realBufferBytes * RAM_MULTIPLIER;
        if (fakeBufferBytes > FAKE_RAM_TOTAL_BYTES) {
            fakeBufferBytes = FAKE_RAM_TOTAL_BYTES;
        }

        info->totalram  = static_cast<unsigned long>(FAKE_RAM_TOTAL_BYTES / unit);
        info->freeram   = static_cast<unsigned long>(fakeFreeBytes / unit);
        info->bufferram = static_cast<unsigned long>(fakeBufferBytes / unit);
    }
    return res;
}

// 2. /proc/meminfo 文件 Hook (纯 C FILE* 解析，无 C++ iostream 依赖)
static int (*orig_openat)(int dirfd, const char *pathname, int flags, mode_t mode) = nullptr;

static std::string generate_fake_meminfo() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return "";

    char line[256];
    std::string newContent;
    newContent.reserve(4096);

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "MemTotal:       %8llu kB\n", (unsigned long long)FAKE_RAM_TOTAL_KB);
            newContent += buf;
        } 
        else if (strncmp(line, "MemFree:", 8) == 0 || 
                 strncmp(line, "MemAvailable:", 13) == 0 || 
                 strncmp(line, "Buffers:", 8) == 0 || 
                 strncmp(line, "Cached:", 7) == 0) {
            
            char key[64] = {0};
            unsigned long long realKb = 0;
            sscanf(line, "%63s %20llu", key, &realKb);

            unsigned long long fakeKb = realKb * RAM_MULTIPLIER;
            if (fakeKb > FAKE_RAM_TOTAL_KB) fakeKb = FAKE_RAM_TOTAL_KB;

            char buf[128];
            snprintf(buf, sizeof(buf), "%-16s%8llu kB\n", key, fakeKb);
            newContent += buf;
        } 
        else {
            newContent += line;
        }
    }
    fclose(fp);
    return newContent;
}

static int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    if (pathname != nullptr && strcmp(pathname, "/proc/meminfo") == 0) {
        std::string fakeData = generate_fake_meminfo();
        if (!fakeData.empty()) {
            int pipefds[2];
            if (pipe2(pipefds, O_CLOEXEC) == 0) {
                write(pipefds[1], fakeData.c_str(), fakeData.size());
                close(pipefds[1]); // 关闭写端，读端可读且达到 EOF 时即结束
                return pipefds[0];  // 返回管道读端文件描述符
            }
        }
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

static void doHook() {
    void *handle = DobbySymbolResolver(nullptr, "__system_property_read_callback");
    if (handle != nullptr) {
        DobbyHook(handle, reinterpret_cast<dobby_dummy_func_t>(my_system_property_read_callback),
                  reinterpret_cast<dobby_dummy_func_t *>(&o_system_property_read_callback));
    }

    // Hook 存储空间 API
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

    // Hook RAM 内存 API
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
