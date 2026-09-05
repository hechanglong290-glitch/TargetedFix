#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <map>
#include <cstdio>
#include <sys/statvfs.h>
#include <sys/vfs.h>

#include "zygisk.hpp"
#include "json/single_include/nlohmann/json.hpp"
#include "dobby.h"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "TFIX/Native", __VA_ARGS__)
#define DEX_FILE_PATH "/data/adb/modules/targetedfix/classes.dex"

// 硬编码伪装容量参数：512GB 总空间，256GB 剩余空间
static constexpr uint64_t FAKE_TOTAL_GB = 512; 
static constexpr uint64_t FAKE_FREE_GB  = 256;

static bool spoofStorage = (FAKE_TOTAL_GB > 0);
static const uint64_t FAKE_BLOCK_SIZE = 4096;
static fsblkcnt_t fakeTotalBlocks = (FAKE_TOTAL_GB * 1024ULL * 1024ULL * 1024ULL) / FAKE_BLOCK_SIZE;
static fsblkcnt_t fakeFreeBlocks  = (FAKE_FREE_GB * 1024ULL * 1024ULL * 1024ULL) / FAKE_BLOCK_SIZE;

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

// ==================== statvfs / statfs / 64位 全路线 Hook 逻辑 ====================
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
        buf->f_bsize   = FAKE_BLOCK_SIZE;
        buf->f_frsize  = FAKE_BLOCK_SIZE;
        buf->f_blocks  = fakeTotalBlocks;
        buf->f_bfree   = fakeFreeBlocks;
        buf->f_bavail  = fakeFreeBlocks;
    }
    return result;
}

static int my_statfs(const char *path, struct statfs *buf) {
    int result = orig_statfs(path, buf);
    if (result == 0 && buf != nullptr && spoofStorage && is_user_storage_path(path)) {
        buf->f_bsize  = FAKE_BLOCK_SIZE;
        buf->f_blocks = fakeTotalBlocks;
        buf->f_bfree  = fakeFreeBlocks;
        buf->f_bavail = fakeFreeBlocks;
    }
    return result;
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
        bool shouldSpoof = false;
        auto rawProcess = env->GetStringUTFChars(args->nice_name, nullptr);
        auto rawDir = env->GetStringUTFChars(args->app_data_dir, nullptr);

        if (rawDir == nullptr || rawProcess == nullptr) {
            if (rawProcess) env->ReleaseStringUTFChars(args->nice_name, rawProcess);
            if (rawDir) env->ReleaseStringUTFChars(args->app_data_dir, rawDir);
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        std::string processStr(rawProcess);

        // 包含设置界面（com.android.settings）与核心进程拦截
        if (processStr != "android" && 
            processStr.find("android.process") == std::string::npos &&
            processStr.find("com.android.systemui") == std::string::npos) {
            shouldSpoof = true; 
        }

        env->ReleaseStringUTFChars(args->nice_name, rawProcess);
        env->ReleaseStringUTFChars(args->app_data_dir, rawDir);

        if (!shouldSpoof) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

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
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
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
