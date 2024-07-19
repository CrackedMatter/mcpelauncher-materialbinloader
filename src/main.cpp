#include <dlfcn.h>
#include <safetyhook.hpp>
#include <string>
#include <utility>
#include "sig.hpp"

struct ResourceLocation {
    int32_t     mFileSystem = 0;
    std::string mPath;
    uint64_t    mPathHash   = 0;
    uint64_t    mFullHash   = 0;

    explicit ResourceLocation(const std::string& path) { mPath = path; }
};

struct ResourcePackManager {
    virtual ~ResourcePackManager() { std::unreachable(); }

    virtual bool load(const ResourceLocation& resourceLocation, std::string& resourceStream) { std::unreachable(); }
};

ResourcePackManager* resourcePackManager;

SafetyHookInline ResourcePackManager_ctor_hook;

void ResourcePackManager_ctor(ResourcePackManager* self, uint64_t a, uint64_t b, bool needsToInitialize) {
    if (needsToInitialize && !resourcePackManager)
        resourcePackManager = self;

    ResourcePackManager_ctor_hook.call(self, a, b, needsToInitialize);
}

SafetyHookInline AppPlatform_readAssetFile_hook;

std::string AppPlatform_readAssetFile(void* self, std::string& filename) {
    if (filename.starts_with("renderer/materials/") || filename.starts_with("assets/renderer/materials/") && filename.ends_with(".material.bin") && resourcePackManager) {
        ResourceLocation resourceLocation(filename.starts_with("assets/") ? filename.substr(7) : filename);
        std::string      resourceStream;

        if (resourcePackManager->load(resourceLocation, resourceStream) && !resourceStream.empty())
            return resourceStream;
    }

    return AppPlatform_readAssetFile_hook.call<std::string>(self, filename);
}

extern "C" __attribute__ ((visibility ("default"))) void mod_preinit() {}

extern "C" __attribute__ ((visibility ("default"))) void mod_init() {
    auto r = getCodeRegion(dlopen("libminecraftpe.so", 0));

    auto ResourcePackManager_ctor_addr = findSig(r, "55 41 57 41 56 53 48 83 EC ? 41 89 CF 49 89 D6 48 89 FB 64 48 8B 04 25 28 00 00 00 48 89 44 24 ? 48 8B 7E");
    ResourcePackManager_ctor_hook = safetyhook::create_inline(ResourcePackManager_ctor_addr, reinterpret_cast<void*>(ResourcePackManager_ctor));

    auto AppPlatform_readAssetFile_addr = findSig(r, "41 57 41 56 41 54 53 48 81 EC ? ? ? ? 49 89 FE 64 48 8B 04 25 28 00 00 00 48 89 84 24 ? ? ? ? 0F 57 C0 0F 29 44 24 ? 48 8D BC 24");
    AppPlatform_readAssetFile_hook = safetyhook::create_inline(AppPlatform_readAssetFile_addr, reinterpret_cast<void*>(AppPlatform_readAssetFile));
}
