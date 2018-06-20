project('largest-tmpfs', 'c')

lib = static_library(
    'largest-tmpfs',
    ['largest-tmpfs.c'],
    install : true)

executable(
    'largest-tmpfs',
    ['main.c'],
    install : true,
    link_with : lib)

executable('largest-tmpfs-fuzz', ['fuzz.c'])

# Installation information:
install_headers('largest-tmpfs.h')
conf_data = configuration_data()
conf_data.set('PACKAGE_VERSION', '0.0.0')
prefix = get_option('prefix')
conf_data.set('libdir', join_paths(prefix, get_option('libdir')))
conf_data.set('includedir', join_paths(prefix, get_option('includedir')))
configure_file(
    input : 'liblargest-tmpfs.pc.in',
    output : 'liblargest-tmpfs.pc',
    configuration : conf_data,
    install_dir : join_paths(prefix, get_option('libdir'), 'pkgconfig'))
