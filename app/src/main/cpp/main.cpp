#include "json.hpp"
#include "shadowhook.h"
#include "zygisk.hpp"
#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "PIF", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PIF", __VA_ARGS__)

/**
 * @brief Reads exactly `count` bytes from the file descriptor `fd` into
 *        `buffer`, unless EOF is reached first. In case of partial reads
 *        (e.g. EOF), the function returns the number of bytes actually read.
 *
 * @param fd     The file descriptor to read from.
 * @param buffer Pointer to the destination buffer.
 * @param count  The total number of bytes to read.
 * @return The total number of bytes read, or -1 on error.
 */
static ssize_t xread(int fd, void *buffer, size_t count) {
    auto *buf = static_cast<char *>(buffer);
    ssize_t totalRead = 0;

    while (count > 0) {
        ssize_t ret = TEMP_FAILURE_RETRY(::read(fd, buf, count));
        if (ret < 0) {
            // Return -1 if we haven't read anything, otherwise return partial read.
            return (totalRead > 0) ? totalRead : -1;
        }
        if (ret == 0) {
            // EOF reached
            break;
        }
        buf += ret;
        count -= ret;
        totalRead += ret;
    }

    return totalRead;
}

/**
 * @brief Writes exactly `count` bytes to the file descriptor `fd` from
 *        `buffer`. This function blocks until all bytes are written or
 *        an error occurs.
 *
 * @param fd     The file descriptor to write to.
 * @param buffer Pointer to the source buffer.
 * @param count  The total number of bytes to write.
 * @return The total number of bytes written, or -1 on error.
 */
static ssize_t xwrite(int fd, const void *buffer, size_t count) {
    auto *buf = static_cast<const char *>(buffer);
    ssize_t totalWritten = 0;

    while (count > 0) {
        ssize_t ret = TEMP_FAILURE_RETRY(::write(fd, buf, count));
        if (ret < 0) {
            // Return -1 if we haven't written anything, otherwise return partial
            // write.
            return (totalWritten > 0) ? totalWritten : -1;
        }
        if (ret == 0) {
            // This is unusual for write(). Typically means the OS can't accept more
            // data right now. Depending on your use case, you might want to retry,
            // sleep, or break. Here, we'll simply break to avoid a potential infinite
            // loop.
            break;
        }
        buf += ret;
        count -= ret;
        totalWritten += ret;
    }

    return totalWritten;
}

static bool DEBUG = false;
static std::string DEVICE_INITIAL_SDK_INT, SECURITY_PATCH, BUILD_ID;

typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);

static T_Callback o_callback = nullptr;

static void modify_callback(void *cookie, const char *name, const char *value,
                            uint32_t serial) {

    if (!cookie || !name || !value || !o_callback)
        return;

    const char *oldValue = value;

    std::string_view prop(name);

    if (prop == "init.svc.adbd") {
        value = "stopped";
    } else if (prop == "sys.usb.state") {
        value = "mtp";
    } else if (prop.ends_with("api_level")) {
        if (!DEVICE_INITIAL_SDK_INT.empty()) {
            value = DEVICE_INITIAL_SDK_INT.c_str();
        }
    } else if (prop.ends_with(".security_patch")) {
        if (!SECURITY_PATCH.empty()) {
            value = SECURITY_PATCH.c_str();
        }
    } else if (prop.ends_with(".build.id")) {
        if (!BUILD_ID.empty()) {
            value = BUILD_ID.c_str();
        }
    }

    if (strcmp(oldValue, value) == 0) {
        if (DEBUG)
            LOGD("[%s]: %s (unchanged)", name, oldValue);
    } else {
        LOGD("[%s]: %s -> %s", name, oldValue, value);
    }

    return o_callback(cookie, name, value, serial);
}

static void (*o_system_property_read_callback)(prop_info *, T_Callback,
                                               void *) = nullptr;

static void my_system_property_read_callback(prop_info *pi, T_Callback callback,
                                             void *cookie) {
    if (pi && callback && cookie)
        o_callback = callback;
    return o_system_property_read_callback(pi, modify_callback, cookie);
}

static bool doHook() {
    shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);

    auto ptr = shadowhook_hook_sym_name(
            "libc.so", "__system_property_read_callback",
            reinterpret_cast<void *>(my_system_property_read_callback),
            reinterpret_cast<void **>(&o_system_property_read_callback));

    if (ptr) {
        LOGD("hook __system_property_read_callback successful at %p", ptr);
        return true;
    }

    LOGE("hook __system_property_read_callback failed!");
    return false;
}

class PlayIntegrityFix : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {

        if (!args) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto dir = env->GetStringUTFChars(args->app_data_dir, nullptr);

        if (!dir) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        bool isGms = std::string_view(dir).ends_with("/com.google.android.gms");

        env->ReleaseStringUTFChars(args->app_data_dir, dir);

        if (!isGms) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

        auto name = env->GetStringUTFChars(args->nice_name, nullptr);

        if (!name) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        bool isGmsUnstable =
                std::string_view(name) == "com.google.android.gms.unstable";

        env->ReleaseStringUTFChars(args->nice_name, name);

        if (!isGmsUnstable) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto gmsDirRaw = env->GetStringUTFChars(args->app_data_dir, nullptr);
        gmsDir = gmsDirRaw;
        env->ReleaseStringUTFChars(args->app_data_dir, gmsDirRaw);

        int fd = api->connectCompanion();

        auto size = static_cast<uint32_t>(gmsDir.size());

        xwrite(fd, &size, sizeof(size));
        xwrite(fd, gmsDir.data(), size);

        bool trickyStore = false;
        xread(fd, &trickyStore, sizeof(trickyStore));

        bool testSignedRom = false;
        xread(fd, &testSignedRom, sizeof(testSignedRom));

        close(fd);

        if (trickyStore) {
            LOGD("TrickyStore module detected!");
            spoofProvider = false;
            spoofProps = false;
        }

        if (testSignedRom) {
            LOGD("--- ROM IS SIGNED WITH TEST KEYS ---");
            spoofSignature = true;
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (gmsDir.empty())
            return;

        FILE *f = fopen((gmsDir + "/pif.json").c_str(), "r");
        if (f) {
            json = nlohmann::json::parse(f, nullptr, false, true);
            fclose(f);
        }
        parseJSON();

        UpdateBuildFields();

        if (spoofProvider || spoofSignature) {
            injectDex();
        } else {
            LOGD("Dex file won't be injected due spoofProvider and spoofSignature "
                 "are false");
        }

        if (spoofProps) {
            if (!doHook()) {
                dlclose();
            }
        } else {
            dlclose();
        }

        json.clear();
        gmsDir.clear();
        gmsDir.shrink_to_fit();
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::string gmsDir;
    nlohmann::json json;
    bool spoofProps = true;
    bool spoofProvider = true;
    bool spoofSignature = false;

    void dlclose() {
        LOGD("dlclose zygisk lib");
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void parseJSON() {
        if (json.empty())
            return;

        if (json.contains("DEVICE_INITIAL_SDK_INT")) {
            if (json["DEVICE_INITIAL_SDK_INT"].is_string()) {
                DEVICE_INITIAL_SDK_INT =
                        json["DEVICE_INITIAL_SDK_INT"].get<std::string>();
            } else if (json["DEVICE_INITIAL_SDK_INT"].is_number_integer()) {
                DEVICE_INITIAL_SDK_INT =
                        std::to_string(json["DEVICE_INITIAL_SDK_INT"].get<int>());
            } else {
                LOGE("Couldn't parse DEVICE_INITIAL_SDK_INT value!");
            }
            json.erase("DEVICE_INITIAL_SDK_INT");
        }

        if (json.contains("spoofProvider") && json["spoofProvider"].is_boolean()) {
            spoofProvider = json["spoofProvider"].get<bool>();
            json.erase("spoofProvider");
        }

        if (json.contains("spoofProps") && json["spoofProps"].is_boolean()) {
            spoofProps = json["spoofProps"].get<bool>();
            json.erase("spoofProps");
        }

        if (json.contains("spoofSignature") &&
            json["spoofSignature"].is_boolean()) {
            spoofSignature = json["spoofSignature"].get<bool>();
            json.erase("spoofSignature");
        }

        if (json.contains("DEBUG") && json["DEBUG"].is_boolean()) {
            DEBUG = json["DEBUG"].get<bool>();
            json.erase("DEBUG");
        }

        if (json.contains("FINGERPRINT") && json["FINGERPRINT"].is_string()) {
            std::string fingerprint = json["FINGERPRINT"].get<std::string>();

            std::vector<std::string> vector;
            auto parts = fingerprint | std::views::split('/');

            for (const auto &part: parts) {
                auto subParts =
                        std::string(part.begin(), part.end()) | std::views::split(':');
                for (const auto &subPart: subParts) {
                    vector.emplace_back(subPart.begin(), subPart.end());
                }
            }

            if (vector.size() == 8) {
                json["BRAND"] = vector[0];
                json["PRODUCT"] = vector[1];
                json["DEVICE"] = vector[2];
                json["RELEASE"] = vector[3];
                json["ID"] = vector[4];
                json["INCREMENTAL"] = vector[5];
                json["TYPE"] = vector[6];
                json["TAGS"] = vector[7];
            } else {
                LOGE("Error parsing fingerprint values!");
            }
        }

        if (json.contains("SECURITY_PATCH") && json["SECURITY_PATCH"].is_string()) {
            SECURITY_PATCH = json["SECURITY_PATCH"].get<std::string>();
        }

        if (json.contains("ID") && json["ID"].is_string()) {
            BUILD_ID = json["ID"].get<std::string>();
        }
    }

    void injectDex() {
        LOGD("get system classloader");
        auto clClass = env->FindClass("java/lang/ClassLoader");
        auto getSystemClassLoader = env->GetStaticMethodID(
                clClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        auto systemClassLoader =
                env->CallStaticObjectMethod(clClass, getSystemClassLoader);

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            return;
        }

        LOGD("create class loader");
        auto dexClClass = env->FindClass("dalvik/system/PathClassLoader");
        auto dexClInit = env->GetMethodID(
                dexClClass, "<init>",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        auto str1 = env->NewStringUTF((gmsDir + "/classes.dex").c_str());
        auto str2 = env->NewStringUTF(gmsDir.c_str());
        auto dexCl =
                env->NewObject(dexClClass, dexClInit, str1, str2, systemClassLoader);

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            return;
        }

        LOGD("load class");
        auto loadClass = env->GetMethodID(clClass, "loadClass",
                                          "(Ljava/lang/String;)Ljava/lang/Class;");
        auto entryClassName =
                env->NewStringUTF("es.chiteroman.playintegrityfix.EntryPoint");
        auto entryClassObj =
                env->CallObjectMethod(dexCl, loadClass, entryClassName);
        auto entryPointClass = (jclass) entryClassObj;

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
            return;
        }

        LOGD("call init");
        auto entryInit = env->GetStaticMethodID(entryPointClass, "init",
                                                "(Ljava/lang/String;ZZ)V");
        auto jsonStr = env->NewStringUTF(json.dump().c_str());
        env->CallStaticVoidMethod(entryPointClass, entryInit, jsonStr,
                                  spoofProvider, spoofSignature);

        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }

        env->DeleteLocalRef(entryClassName);
        env->DeleteLocalRef(entryClassObj);
        env->DeleteLocalRef(jsonStr);
        env->DeleteLocalRef(dexCl);
        env->DeleteLocalRef(dexClClass);
        env->DeleteLocalRef(clClass);

        LOGD("jni memory free");
    }

    void UpdateBuildFields() {
        jclass buildClass = env->FindClass("android/os/Build");
        jclass versionClass = env->FindClass("android/os/Build$VERSION");

        for (auto &[key, val]: json.items()) {
            if (!val.is_string())
                continue;

            const char *fieldName = key.c_str();

            jfieldID fieldID =
                    env->GetStaticFieldID(buildClass, fieldName, "Ljava/lang/String;");

            if (env->ExceptionCheck()) {
                env->ExceptionClear();

                fieldID = env->GetStaticFieldID(versionClass, fieldName,
                                                "Ljava/lang/String;");

                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    continue;
                }
            }

            if (fieldID != nullptr) {
                std::string str = val.get<std::string>();
                const char *value = str.c_str();
                jstring jValue = env->NewStringUTF(value);

                env->SetStaticObjectField(buildClass, fieldID, jValue);
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    continue;
                }

                LOGD("Set '%s' to '%s'", fieldName, value);
            }
        }
    }
};

static bool checkOtaZip() {
    std::array<char, 128> buffer{};
    std::string result;
    bool found = false;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(
            popen("unzip -l /system/etc/security/otacerts.zip", "r"), pclose);
    if (!pipe)
        return false;

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
        if (result.find("test") != std::string::npos) {
            found = true;
            break;
        }
    }

    return found;
}

namespace fs = std::filesystem;

static void companion(int fd) {

    uint32_t size = 0;
    xread(fd, &size, sizeof(size));

    std::string gmsDir(size, '\0');

    xread(fd, &gmsDir[0], size);

    LOGD("[ROOT] GMS dir: %s", gmsDir.c_str());

    std::string PIF_PATH = "/data/adb/modules/playintegrityfix";

    std::string DEX_FILE = PIF_PATH + "/classes.dex";
    std::string NEW_DEX_FILE = gmsDir + "/classes.dex";

    std::string JSON_FILE = "/data/adb/pif.json";
    std::string JSON_FILE_2 = PIF_PATH + "/custom.pif.json";
    std::string JSON_FILE_DEFAULT = PIF_PATH + "/pif.json";
    std::string NEW_JSON_FILE = gmsDir + "/pif.json";

    std::string SHADOWHOOK_DIR;

#if __aarch64__
    SHADOWHOOK_DIR = PIF_PATH + "/shadowhook/arm64-v8a";
#elif __arm__
    SHADOWHOOK_DIR = PIF_PATH + "/shadowhook/armeabi-v7a";
#endif

    if (fs::exists(DEX_FILE)) {
        if (fs::copy_file(DEX_FILE, NEW_DEX_FILE,
                          fs::copy_options::overwrite_existing)) {
            fs::permissions(NEW_DEX_FILE, fs::perms::owner_read |
                                          fs::perms::group_read |
                                          fs::perms::others_read);
        }
    }

    bool copy = false;

    if (fs::exists(JSON_FILE)) {
        copy = fs::copy_file(JSON_FILE, NEW_JSON_FILE,
                             fs::copy_options::overwrite_existing);
    } else if (fs::exists(JSON_FILE_2)) {
        copy = fs::copy_file(JSON_FILE_2, NEW_JSON_FILE,
                             fs::copy_options::overwrite_existing);
    } else if (fs::exists(JSON_FILE_DEFAULT)) {
        copy = fs::copy_file(JSON_FILE_DEFAULT, NEW_JSON_FILE,
                             fs::copy_options::overwrite_existing);
    }

    if (copy) {
        fs::permissions(NEW_JSON_FILE, fs::perms::all);
    }

    if (fs::exists(SHADOWHOOK_DIR)) {
        for (const auto &entry: fs::directory_iterator(SHADOWHOOK_DIR)) {
            if (fs::is_regular_file(entry.status())) {
                fs::path targetPath = gmsDir / entry.path().filename();
                fs::copy_file(entry.path(), targetPath,
                              fs::copy_options::overwrite_existing);
            }
        }
    }

    std::string ts("/data/adb/modules/tricky_store");
    bool trickyStore = fs::exists(ts) && !fs::exists(ts + "/disable") &&
                       !fs::exists(ts + "/remove");
    xwrite(fd, &trickyStore, sizeof(trickyStore));

    bool testSignedRom = checkOtaZip();
    xwrite(fd, &testSignedRom, sizeof(testSignedRom));
}

REGISTER_ZYGISK_MODULE(PlayIntegrityFix)

REGISTER_ZYGISK_COMPANION(companion)
