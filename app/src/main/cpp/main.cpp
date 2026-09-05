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
#define PROP_FILE_PATH "/data/adb/modules/targetedfix/config/fix.prop"
#define JSON_FILE_PATH "/data/adb/modules/targetedfix/config/fix.json"

static int verboseLogs = 0;
static int spoofBuild = 1;
static int spoofProps = 1;
static int spoofProvider = 0;
static int spoofSignature = 0;

// ==================== 存储空间伪装全局变量 ====================
static bool spoofStorage = false;
static const uint64_t FAKE_BLOCK_SIZE = 4096; // 4KB 逻辑块大小
static fsblkcnt_t fakeTotalBlocks = 0;
static fsblkcnt_t fakeFreeBlocks = 0;

static std::map<std::string, std::string> jsonProps;

typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);

static std::map<void *, T_Callback> callbacks;

static void modify_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (cookie == nullptr || name == nullptr || value == nullptr || !callbacks.contains(cookie)) return;

    const char *oldValue = value;
    std::string prop(name);

    if (jsonProps.count(prop)) {
        value = jsonProps[prop].c_str();
    } else {
        for (const auto &p: jsonProps) {
            if (p.first.starts_with("*") && prop.ends_with(p.first.substr(1))) {
                value = p.second.c_str();
                break;
            }
        }
    }

    if (oldValue == value) {
        if (verboseLogs > 99) LOGD("[%s]: %s (unchanged)", name, oldValue);
    } else {
        LOGD("[%s]: %s -> %s", name, oldValue, value);
    }

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

// ==================== statvfs / statfs Hook 逻辑 ====================
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
        if (verboseLogs > 0) LOGD("Hooked statvfs for path: %s", path);
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
        if (verboseLogs > 0) LOGD("Hooked statfs for path: %s", path);
    }
    return result;
}

static void doHook() {
    void *handle = DobbySymbolResolver(nullptr, "__system_property_read_callback");
    if (handle == nullptr) {
        LOGD("Couldn't find '__system_property_read_callback' handle");
    } else {
        LOGD("Found '__system_property_read_callback' handle at %p", handle);
        DobbyHook(handle, reinterpret_cast<dobby_dummy_func_t>(my_system_property_read_callback),
                  reinterpret_cast<dobby_dummy_func_t *>(&o_system_property_read_callback));
    }

    if (spoofStorage) {
        void* statvfs_ptr = DobbySymbolResolver(nullptr, "statvfs");
        if (statvfs_ptr) {
            DobbyHook(statvfs_ptr, reinterpret_cast<dobby_dummy_func_t>(my_statvfs),
                      reinterpret_cast<dobby_dummy_func_t*>(&orig_statvfs));
            LOGD("Hooked statvfs at %p", statvfs_ptr);
        }

        void* statfs_ptr = DobbySymbolResolver(nullptr, "statfs");
        if (statfs_ptr) {
            DobbyHook(statfs_ptr, reinterpret_cast<dobby_dummy_func_t>(my_statfs),
                      reinterpret_cast<dobby_dummy_func_t*>(&orig_statfs));
            LOGD("Hooked statfs at %p", statfs_ptr);
        }
    }
}

static void setFieldNative(JNIEnv *env, jclass /* clazz_EntryPoint */, jclass targetClass, jobject fieldObj, jstring typeObj, jobject valueObj) {
    if (!targetClass || !fieldObj || !typeObj) return;

    jfieldID fieldID = env->FromReflectedField(fieldObj);
    if (!fieldID) return;

    const char *typeName = env->GetStringUTFChars(typeObj, nullptr);

    if (strcmp(typeName, "java.lang.String") == 0) {
        env->SetStaticObjectField(targetClass, fieldID, valueObj);
    } else if (strcmp(typeName, "int") == 0) {
        jclass intClass = env->FindClass("java/lang/Integer");
        jmethodID intValue = env->GetMethodID(intClass, "intValue", "()I");
        jint val = env->CallIntMethod(valueObj, intValue);
        env->SetStaticIntField(targetClass, fieldID, val);
    } else if (strcmp(typeName, "long") == 0) {
        jclass longClass = env->FindClass("java/lang/Long");
        jmethodID longValue = env->GetMethodID(longClass, "longValue", "()J");
        jlong val = env->CallLongMethod(valueObj, longValue);
        env->SetStaticLongField(targetClass, fieldID, val);
    } else if (strcmp(typeName, "boolean") == 0) {
        jclass boolClass = env->FindClass("java/lang/Boolean");
        jmethodID booleanValue = env->GetMethodID(boolClass, "booleanValue", "()Z");
        jboolean val = env->CallBooleanMethod(valueObj, booleanValue);
        env->SetStaticBooleanField(targetClass, fieldID, val);
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

        pkgName = rawProcess;
        std::string processStr(rawProcess);

        // ==================== 全局 App 过滤（包含系统设置，排除底层系统进程） ====================
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

        long dexSize = 0, jsonSize = 0;
        int fd = api->connectCompanion();

        long processSize = processStr.size();
        write(fd, &processSize, sizeof(long));
        write(fd, processStr.data(), processSize);

        read(fd, &dexSize, sizeof(long));
        read(fd, &jsonSize, sizeof(long));

        if (dexSize < 1 || jsonSize < 1) {
            close(fd);
            LOGD("Couldn't read required files");
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        dexVector.resize(dexSize);
        read(fd, dexVector.data(), dexSize);

        jsonVector.resize(jsonSize);
        read(fd, jsonVector.data(), jsonSize);

        close(fd);

        std::string configString(jsonVector.cbegin(), jsonVector.cend());
        jsonVector.clear();

        if (!nlohmann::json::accept(configString, true)) {
            LOGD("Converting config from prop format to JSON format");

            configString.erase(std::remove(configString.begin(), configString.end(), '\r'), configString.end());

            std::string jsonString = "{";
            char propDelimiter = '=';
            char commentDelimiter = '#';
            size_t beginPos = 0, endPos = 0;
            while ((endPos = configString.find('\n', beginPos)) != std::string::npos) {
                std::string line = configString.substr(beginPos, endPos - beginPos);
                beginPos = endPos + 1;
                if (line.empty() || line[0] == '#') continue;
                std::string name, value;
                size_t propDelimiterPos = line.find(propDelimiter);
                if (propDelimiterPos != std::string::npos) {
                    name = line.substr(0, propDelimiterPos);
                    value = line.substr(propDelimiterPos + 1);
                } else {
                    continue;
                }
                size_t commentDelimiterPos = value.find(commentDelimiter);
                if (commentDelimiterPos != std::string::npos) {
                    value = value.substr(0, commentDelimiterPos);
                    size_t lastPos = value.find_last_not_of(" ");
                    if (lastPos != std::string::npos) value.resize(lastPos + 1);
                }
                if (!name.empty()) {
                    jsonString += "\n\"" + name + "\": \"" + value + "\",";
                }
            }
            if (jsonString.back() == ',') jsonString.pop_back();
            jsonString += "\n}\n";

            configString = jsonString;
        }

        json = nlohmann::json::parse(configString, nullptr, false, true);
        configString.clear();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (dexVector.empty() || json.empty()) return;

        readJson();

        if (spoofProps > 0 || spoofStorage) doHook();
        if (spoofBuild + spoofProvider + spoofSignature > 0) inject();

        dexVector.clear();
        json.clear();
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::vector<char> dexVector;
    std::vector<char> jsonVector;
    nlohmann::json json;
    std::string pkgName;

    void readJson() {
        LOGD("JSON contains %d keys!", static_cast<int>(json.size()));

        if (json.contains("verboseLogs")) {
            if (!json["verboseLogs"].is_null() && json["verboseLogs"].is_string() && json["verboseLogs"] != "") {
                verboseLogs = stoi(json["verboseLogs"].get<std::string>());
                if (verboseLogs > 0) LOGD("Verbose logging (level %d) enabled!", verboseLogs);
            }
            json.erase("verboseLogs");
        }

        if (json.contains("spoofBuild")) {
            if (!json["spoofBuild"].is_null() && json["spoofBuild"].is_string() && json["spoofBuild"] != "") {
                spoofBuild = stoi(json["spoofBuild"].get<std::string>());
            }
            json.erase("spoofBuild");
        }
        if (json.contains("spoofProps")) {
            if (!json["spoofProps"].is_null() && json["spoofProps"].is_string() && json["spoofProps"] != "") {
                spoofProps = stoi(json["spoofProps"].get<std::string>());
            }
            json.erase("spoofProps");
        }
        if (json.contains("spoofProvider")) {
            if (!json["spoofProvider"].is_null() && json["spoofProvider"].is_string() && json["spoofProvider"] != "") {
                spoofProvider = stoi(json["spoofProvider"].get<std::string>());
            }
            json.erase("spoofProvider");
        }
        if (json.contains("spoofSignature")) {
            if (!json["spoofSignature"].is_null() && json["spoofSignature"].is_string() && json["spoofSignature"] != "") {
                spoofSignature = stoi(json["spoofSignature"].get<std::string>());
            }
            json.erase("spoofSignature");
        }

        // ==================== 解析 FAKE_TOTAL_GB 与 FAKE_FREE_GB ====================
        uint64_t totalGb = 0, freeGb = 0;
        if (json.contains("FAKE_TOTAL_GB")) {
            if (!json["FAKE_TOTAL_GB"].is_null() && json["FAKE_TOTAL_GB"].is_string() && json["FAKE_TOTAL_GB"] != "") {
                totalGb = std::stoull(json["FAKE_TOTAL_GB"].get<std::string>());
            }
            json.erase("FAKE_TOTAL_GB");
        }
        if (json.contains("FAKE_FREE_GB")) {
            if (!json["FAKE_FREE_GB"].is_null() && json["FAKE_FREE_GB"].is_string() && json["FAKE_FREE_GB"] != "") {
                freeGb = std::stoull(json["FAKE_FREE_GB"].get<std::string>());
            }
            json.erase("FAKE_FREE_GB");
        }

        if (totalGb > 0 && freeGb > 0) {
            uint64_t totalBytes = totalGb * 1024ULL * 1024ULL * 1024ULL;
            uint64_t freeBytes  = freeGb  * 1024ULL * 1024ULL * 1024ULL;
            fakeTotalBlocks = totalBytes / FAKE_BLOCK_SIZE;
            fakeFreeBlocks  = freeBytes / FAKE_BLOCK_SIZE;
            spoofStorage = true;
            LOGD("Storage Spoofing enabled: Total %llu GB, Free %llu GB", (unsigned long long)totalGb, (unsigned long long)freeGb);
        }

        std::vector<std::string> eraseKeys;
        for (auto &jsonList: json.items()) {
            if (verboseLogs > 1) LOGD("Parsing %s", jsonList.key().c_str());
            if (jsonList.key().find_first_of("*.") != std::string::npos) {
                if (!jsonList.value().is_null() && jsonList.value().is_string()) {
                    if (jsonList.value() == "") {
                        jsonProps[jsonList.key()] = "";
                    } else {
                        jsonProps[jsonList.key()] = jsonList.value();
                    }
                }
                eraseKeys.push_back(jsonList.key());
            }
        }
        for (auto key: eraseKeys) {
            if (json.contains(key)) json.erase(key);
        }
    }

    void inject() {
        const char* niceName = "APP";

        LOGD("JNI %s: Getting system classloader", niceName);
        auto clClass = env->FindClass("java/lang/ClassLoader");
        auto getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        auto systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);

        LOGD("JNI %s: Creating module classloader", niceName);
        auto dexClClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        auto dexClInit = env->GetMethodID(dexClClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        auto buffer = env->NewDirectByteBuffer(dexVector.data(), static_cast<jlong>(dexVector.size()));
        auto dexCl = env->NewObject(dexClClass, dexClInit, buffer, systemClassLoader);

        LOGD("JNI %s: Loading module class", niceName);
        auto loadClass = env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");        
        const char* className = "es.chiteroman.playintegrityfix.EntryPoint";
        auto entryClassName = env->NewStringUTF(className);
        auto entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);

        auto entryClass = (jclass) entryClassObj;

        JNINativeMethod methods[] = {
            {"setFieldNative", "(Ljava/lang/Class;Ljava/lang/reflect/Field;Ljava/lang/String;Ljava/lang/Object;)V", (void*) setFieldNative}
        };
        env->RegisterNatives(entryClass, methods, 1);

        LOGD("JNI %s: Sending JSON", niceName);
        auto receiveJson = env->GetStaticMethodID(entryClass, "receiveJson", "(Ljava/lang/String;)V");
        auto javaStr = env->NewStringUTF(json.dump().c_str());
        env->CallStaticVoidMethod(entryClass, receiveJson, javaStr);

        LOGD("JNI %s: Calling EntryPoint.init", niceName);
        auto entryInit = env->GetStaticMethodID(entryClass, "init", "(IIII)V");
        auto javaVerbose = verboseLogs;
        auto javaBuild = spoofBuild;
        auto javaProvider = spoofProvider;
        auto javaSignature = spoofSignature;
        env->CallStaticVoidMethod(entryClass, entryInit, javaVerbose, javaBuild, javaProvider, javaSignature);

        env->DeleteLocalRef(javaStr);
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
    long dexSize = 0, jsonSize = 0;
    std::vector<char> dexVector, jsonVector;

    std::string processName;
    long processSize = 0;
    read(fd, &processSize, sizeof(long));
    processName.resize(processSize);
    read(fd, processName.data(), processSize);

    std::replace(processName.begin(), processName.end(), ':', '.');

    FILE *dex = fopen(DEX_FILE_PATH, "rb");
    if (dex) {
        fseek(dex, 0, SEEK_END);
        dexSize = ftell(dex);
        fseek(dex, 0, SEEK_SET);

        dexVector.resize(dexSize);
        fread(dexVector.data(), 1, dexSize, dex);

        fclose(dex);
    }

    FILE *json = nullptr;

    std::string customPropPath = "/data/adb/modules/targetedfix/config/" + processName + ".prop";
    json = fopen(customPropPath.c_str(), "r");

    if (!json) {
        std::string customJsonPath = "/data/adb/modules/targetedfix/config/" + processName + ".json";
        json = fopen(customJsonPath.c_str(), "r");
    }

    if (!json) {
        json = fopen(PROP_FILE_PATH, "r");
    }

    if (!json) {
        json = fopen(JSON_FILE_PATH, "r");
    }

    if (json) {
        fseek(json, 0, SEEK_END);
        jsonSize = ftell(json);
        fseek(json, 0, SEEK_SET);

        jsonVector.resize(jsonSize);
        fread(jsonVector.data(), 1, jsonSize, json);

        fclose(json);
    }

    write(fd, &dexSize, sizeof(long));
    write(fd, &jsonSize, sizeof(long));

    write(fd, dexVector.data(), dexSize);
    write(fd, jsonVector.data(), jsonSize);
}

REGISTER_ZYGISK_MODULE(TargetedFix)

REGISTER_ZYGISK_COMPANION(companion)
