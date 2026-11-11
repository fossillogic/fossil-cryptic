add_project_arguments('-D_POSIX_C_SOURCE=200112L', language: 'c')
add_project_arguments('-D_POSIX_C_SOURCE=200112L', language: 'cpp')
cc = meson.get_compiler('c')

libdl = cc.find_library('dl', required: false)
libm = cc.find_library('m', required: false)

# ------------------------------
# Platform-specific dependencies
# ------------------------------
platform_deps = []

if host_machine.system() == 'windows'
    platform_deps += [
        cc.find_library('ws2_32', required: true),
        cc.find_library('iphlpapi', required: true),
        cc.find_library('bcrypt', required: true),
        cc.find_library('dxgi', required: true)
    ]
endif

if host_machine.system() == 'darwin'
    platform_deps += []
endif

# Linux has no extra libraries (keep empty)
if host_machine.system() == 'linux'
    platform_deps += []
endif

platform_deps += libdl
platform_deps += libm