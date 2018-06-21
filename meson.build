project('largest-tmpfs', 'c')

version_cmd = run_command('cat', join_paths(meson.source_root(), 'version.txt'))
package_version = version_cmd.stdout().strip()

comp = find_program('create-config.h.sh')

config_h = custom_target(
    'config.h',
    output : 'config.h',
    input : 'version.txt',
    command : [comp, '@INPUT@', '@OUTPUT@'])

lib = static_library(
    'largest-tmpfs',
    ['largest-tmpfs.c', config_h],
    install : true)

executable(
    'largest-tmpfs',
    ['main.c'],
    install : true,
    link_with : lib,
    c_args : ['-DHAVE_CONFIG_H'])

executable('largest-tmpfs-fuzz', ['fuzz.c'])

# Installation information:
install_headers('largest-tmpfs.h')
conf_data = configuration_data()
conf_data.set('PACKAGE_VERSION', package_version)
prefix = get_option('prefix')
conf_data.set('libdir', join_paths(prefix, get_option('libdir')))
conf_data.set('includedir', join_paths(prefix, get_option('includedir')))
configure_file(
    input : 'liblargest-tmpfs.pc.in',
    output : 'liblargest-tmpfs.pc',
    configuration : conf_data,
    install_dir : join_paths(prefix, get_option('libdir'), 'pkgconfig'))
