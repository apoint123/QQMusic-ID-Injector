# GEMINI.md - AI Context File

This document provides an overview of the **QQMusic-ID-Injector** project, its architecture, and development conventions. It is intended to be used as a contextual reference for AI-powered development assistance.

## 1. Project Overview
**Goal**: To precisely identify the song currently playing in the Tencent QQ Music Windows client (32-bit).
**Mechanism**: The project reads the internal Song ID from QQ Music's memory and injects this ID into the Windows **SMTC** (System Media Transport Controls) metadata, specifically into the `Genres` field. This allows third-party software to read the exact ID via standard Windows APIs without needing to hack the music client themselves.

## 2. Technical Stack
* **Language**: Rust
* **Target Architecture**: `i686-pc-windows-msvc` (32-bit, mandatory to match QQ Music).
* **Key Crates**:
    * `windows`: For Win32, COM, and WinRT interactions.
    * `minhook`: For hooking the VTable of SMTC COM objects.
    * `winreg`: For finding the QQ Music installation path.

## 3. Architecture & Components

The project consists of a **Cargo Workspace** with two members:

### A. Payload (`payload.dll` -> Renamed to `msimg32.dll`)
This is a **DLL Proxy** (Hijack) module that runs inside the `QQMusic.exe` process.

* **DLL Proxying**:
    * Impersonates the system library `msimg32.dll`.
    * Forwards these calls to the original system DLL.
* **Memory Logic**:
    * **Pattern Scanning**: Searches `QQMusic.dll` memory for a specific byte signature (`A2 ?? ?? ?? ?? A3 ...`) to find the `CurrentSongInfo` structure.
    * **Lazy Scanning**: Scanning only occurs once, the first time the SMTC `Update` method is called.
    * **Data Access**: Reads the Song ID from offset `0x60` of the structure found.
* **Hooking Logic**:
    * **Target**: `ISystemMediaTransportControlsDisplayUpdater::Update` (VTable Index 17).
    * **Implementation**:
        1.  Intercepts the `Update` call.
        2.  Reads the current Song ID from memory.
        3.  Manually invokes `MusicProperties` (VTable Index 12) via raw pointer arithmetic.
        4.  Clears the `Genres` list and appends the Song ID as a string.
        5.  Calls the original `Update` function to broadcast changes to Windows.

### B. Installer
This is a standalone, single-file installer.

* **Discovery**: Locates QQ Music via Windows Registry (`HKLM` or `HKCU` keys).

## 4. Key Technical Implementation Details

### The Hook
We use a VTable hook on the WinRT `DisplayUpdater` object.
* **Interface**: `ISystemMediaTransportControlsDisplayUpdater`
* **Update Method Index**: 17
* **MusicProperties Method Index**: 12
* **Property Used**: `MusicDisplayProperties.Genres` (Vector of Strings).

### The Memory Pattern
* **Signature**: `A2 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A2 ?? ?? ?? ?? A3`
* **Offset**: The 4 bytes following the first `A2` are the pointer to the `CurrentSongInfo` structure pointer.
* **Song ID Offset**: `0x60` relative to the structure base.
