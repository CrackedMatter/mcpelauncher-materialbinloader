#include <dlfcn.h>
#include <libhat/scanner.hpp>
#include <link.h>
#include <optional>
#include <safetyhook.hpp>
#include <string>
#include <utility>

struct ResourceLocation {
    int32_t     mFileSystem = 0;
    std::string mPath;
    uint64_t    mPathHash = 0;
    uint64_t    mFullHash = 0;

    explicit ResourceLocation(std::string path) : mPath{std::move(path)} {}
};

struct ResourcePackManager {
    virtual ~ResourcePackManager();

    virtual bool load(const ResourceLocation& resourceLocation, std::string& resourceStream);
};

ResourcePackManager* resourcePackManager{};

SafetyHookInline ResourcePackManager_ctor_hook;

void ResourcePackManager_ctor(ResourcePackManager* self, uint64_t a, uint64_t b, bool needsToInitialize) {
    if (needsToInitialize && !resourcePackManager)
        resourcePackManager = self;

    ResourcePackManager_ctor_hook.call(self, a, b, needsToInitialize);
}

std::optional<std::string> loadMaterial(const std::string& filename) {
    if ((filename.starts_with("renderer/materials/") || filename.starts_with("assets/renderer/materials/")) && filename.ends_with(".material.bin") && resourcePackManager) {
        ResourceLocation resourceLocation{filename.starts_with("assets/") ? filename.substr(7) : filename};
        std::string      resourceStream;

        if (resourcePackManager->load(resourceLocation, resourceStream) && !resourceStream.empty())
            return resourceStream;
    }

    return std::nullopt;
}

SafetyHookInline readAssetFile_hook;

std::string readAssetFile(const std::string& filename) {
    return loadMaterial(filename).value_or(readAssetFile_hook.call<std::string, const std::string&>(filename));
}

std::string AppPlatform_readAssetFile(void* self, const std::string& filename) {
    return loadMaterial(filename).value_or(readAssetFile_hook.call<std::string, void*, const std::string&>(self, filename));
}

extern "C" [[gnu::visibility("default")]] void mod_preinit() {}

extern "C" [[gnu::visibility("default")]] void mod_init() {
    using namespace hat::literals::signature_literals;

    auto mc = dlopen("libminecraftpe.so", 0);

    std::span<std::byte> r;

    auto l = [&](dl_phdr_info* info) {
        if (auto h = dlopen(info->dlpi_name, RTLD_NOLOAD); dlclose(h), h != mc)
            return 0;
        r = {reinterpret_cast<std::byte*>(info->dlpi_addr + info->dlpi_phdr[1].p_vaddr), info->dlpi_phdr[1].p_memsz};
        return 1;
    };

    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) { return (*static_cast<decltype(l)*>(data))(info); }, &l);

    auto scan = [r](const auto&... sig) {
        void* addr;
        ((addr = hat::find_pattern(r, sig, hat::scan_alignment::X16).get()) || ...);
        return addr;
    };

    auto ResourcePackManager_ctor_addr = scan(
        "55 41 57 41 56 41 55 41 54 53 48 83 EC ? 41 89 CF 49 89 D6 48 89 FB 64 48 8B 04 25 28 00 00 00 48 89 44 24 ? 48 8B 7E"_sig,
        "55 41 57 41 56 53 48 83 EC ? 41 89 CF 49 89 D6 48 89 FB 64 48 8B 04 25 28 00 00 00 48 89 44 24 ? 48 8B 7E"_sig);

    ResourcePackManager_ctor_hook = safetyhook::create_inline(ResourcePackManager_ctor_addr, ResourcePackManager_ctor);

    auto readAssetFile_addr = scan(
        "41 57 41 56 41 54 53 48 81 EC E8 00 00 00 49 89 FE 64 48 8B 04 25 28 00 00 00 48 89 84 24 ? ? ? ? 0F 57 C0 0F 29 44 24 ? 0F B6 06"_sig);

    if (readAssetFile_addr) {
        readAssetFile_hook = safetyhook::create_inline(readAssetFile_addr, readAssetFile);
    } else {
        auto AppPlatform_readAssetFile_addr = scan(
            "41 57 41 56 41 54 53 48 81 EC ? ? ? ? 49 89 FE 64 48 8B 04 25 28 00 00 00 48 89 84 24 ? ? ? ? 0F 57 C0 0F 29 44 24 ? 0F B6 02"_sig,
            "41 57 41 56 41 54 53 48 81 EC ? ? ? ? 49 89 FE 64 48 8B 04 25 28 00 00 00 48 89 84 24 ? ? ? ? 0F 57 C0 0F 29 44 24 ? 48 8D BC 24"_sig);

        readAssetFile_hook = safetyhook::create_inline(AppPlatform_readAssetFile_addr, AppPlatform_readAssetFile);
    }
}
