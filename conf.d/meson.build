conf_d_dir = get_option('sysconfdir') / 'conf.d'

conf_common = [
  'bootmisc',
  'fsck',
  'hostname',
  'localmount',
  'netmount',
  'swap',
  'swclock',
  ]

conf_net = [
  'network',
  'staticroute',
  ]

conf_FreeBSD = [
  'ipfw',
  'modules',
  'moused',
  'powerd',
  'rarpd',
  'savecore',
  'syscons',
  'urandom',
  ]

conf_Linux = [
  'agetty',
  'consolefont',
  'devfs',
  'dmesg',
  'hwclock',
  'keymaps',
  'killprocs',
  'modules',
  'mtab',
  'net-online',
  'seedrng',
  ]

conf_NetBSD =  [
  'moused',
  'rarpd',
  'savecore',
  'urandom',
  ]

conf_data = conf_common
if get_option('newnet')
  conf_data = conf_data + conf_net
endif
if os == 'freebsd'
  conf_data = conf_data + conf_FreeBSD
elif os == 'linux'
  conf_data = conf_data + conf_Linux
elif os == 'netbsd'
  conf_data = conf_data + conf_NetBSD
endif

install_data(conf_data, install_dir : conf_d_dir)
