#include "sig.hpp"
#include <algorithm>
#include <dlfcn.h>
#include <link.h>
#include <ranges>
#include <span>
#include <string>
#include <tuple>
#include <vector>

constexpr uint8_t parseNibble(char c) {
    return (c >= '0' && c <= '9') ? (c - '0') : (c >= 'A' && c <= 'F') ? (c - 'A' + 0xA) : 0;
}

struct SigElement {
    uint8_t byte = 0;
    uint8_t mask = 0;

    explicit constexpr SigElement(const std::string& str) {
        if (str != "?") {
            byte |= parseNibble(str[0]) << 4;
            byte |= parseNibble(str[1]);
            mask = 0xFF;
        }
    }

    bool operator==(uint8_t rhs) const {
        return byte == (rhs & mask);
    }
};

void* findSig(std::span<uint8_t> range, const std::string& str) {
    auto sig = str
               | std::views::split(' ')
               | std::views::transform([](auto&& r) { return SigElement({r.begin(), r.end()}); })
               | std::ranges::to<std::vector>();

    auto it = std::search(range.begin(), range.end(), sig.begin(), sig.end());
    return it != range.end() ? std::to_address(it) : nullptr;
}

std::span<uint8_t> getCodeRegion(void* handle) {
    auto data = std::make_tuple(std::span<uint8_t>{}, handle);

    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data_) -> int {
        auto& [range, h1] = *static_cast<decltype(data)*>(data_);

        auto h2 = dlopen(info->dlpi_name, RTLD_NOLOAD);
        dlclose(h2);
        if (h1 != h2)
            return 0;

        for (auto& phdr: std::span(info->dlpi_phdr, info->dlpi_phnum)) {
            if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
                range = {reinterpret_cast<uint8_t*>(info->dlpi_addr + phdr.p_vaddr), phdr.p_memsz};
                break;
            }
        }

        return 1;
    }, &data);

    return std::get<0>(data);
}
