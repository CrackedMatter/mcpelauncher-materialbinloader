#include <dlfcn.h>
#include <libhat/Scanner.hpp>
#include <link.h>
#include <safetyhook.hpp>
#include <string>
#include <utility>

struct ResourceLocation {
    int32_t     mFileSystem = 0;
    std::string mPath;
    uint64_t    mPathHash = 0;
    uint64_t    mFullHash = 0;

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

extern "C" [[gnu::visibility("default")]] void mod_preinit() {}

extern "C" [[gnu::visibility("default")]] void mod_init() {
    using namespace hat::literals::signature_literals;

    static std::span<std::byte> r;

    dl_iterate_phdr(
        [](dl_phdr_info* info, size_t, void* mc) {
            auto h = dlopen(info->dlpi_name, RTLD_NOLOAD);
            dlclose(h);
            if (h == mc) {
                for (auto& phdr : std::span{info->dlpi_phdr, info->dlpi_phnum}) {
                    if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
                        r = {reinterpret_cast<std::byte*>(info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz};
                        return 1;
                    }
                }
            }
            return 0;
        },
        dlopen("libminecraftpe.so", 0));

    auto ResourcePackManager_ctor_addr = hat::find_pattern(
        r, "55 41 57 41 56 41 55 41 54 53 48 83 EC ? 41 89 CF 49 89 D6 48 89 FB 64 48 8B 04 25 28 00 00 00 48 89 44 24 ? 48 8B 7E"_sig,
        hat::scan_alignment::X16);

    ResourcePackManager_ctor_hook = safetyhook::create_inline(ResourcePackManager_ctor_addr.get(), ResourcePackManager_ctor);

    auto AppPlatform_readAssetFile_addr = hat::find_pattern(
        r, "41 57 41 56 41 54 53 48 81 EC ? ? ? ? 49 89 FE 64 48 8B 04 25 28 00 00 00 48 89 84 24 ? ? ? ? 0F 57 C0 0F 29 44 24 ? 0F B6 02 A8"_sig,
        hat::scan_alignment::X16);

    AppPlatform_readAssetFile_hook = safetyhook::create_inline(AppPlatform_readAssetFile_addr.get(), AppPlatform_readAssetFile);
}
