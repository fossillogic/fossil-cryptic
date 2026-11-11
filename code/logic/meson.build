dir = include_directories('.')

subdir('fossil')

fossil_cryptic_lib = library('fossil_cryptic',
    files(
        'hash.c',
        'auth.c',
        'cipher.c',
        'keygen.c',
        'rand.c',
        'aead.c',
        'aes.c'),
    install: true,
    dependencies: [dependency('threads'), platform_deps],
    include_directories: dir)

fossil_cryptic_dep = declare_dependency(
    link_with: [fossil_cryptic_lib],
    include_directories: dir)

meson.override_dependency('fossil-cryptic', fossil_cryptic_dep)
