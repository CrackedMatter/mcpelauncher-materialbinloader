# mcpelauncher-materialbinloader

A port of [MaterialBinLoader](https://github.com/ddf8196/MaterialBinLoader) for mcpelauncher.

## Usage

Create a `mods` directory in the direcotry of your mcpelauncher profile (e.g. `~/.local/share/mcpelauncher`) if you have not already done so.
Download the mod from [releases](https://github.com/CrackedMatter/mcpelauncher-materialbinloader/releases) and move the file into the `mods` directory.


## Building

Prerequisites:

- Android NDK r27 or later. [Download](https://developer.android.com/ndk/downloads)
- CMake 3.15 or later

Replace `/path/to/ndk` with the path to the Android NDK:

```
cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/ndk/build/cmake/android.toolchain.cmake -DANDROID_ABI=x86_64 -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build
```

This will create a `build` directory containing the mod file. Install it as described in [Usage](#usage).
