#pragma once

#include <span>
#include <string>

[[nodiscard]] void* findSig(std::span<uint8_t> range, const std::string& str);

[[nodiscard]] std::span<uint8_t> getCodeRegion(void* handle);
