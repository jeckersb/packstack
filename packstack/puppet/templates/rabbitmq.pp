class { '::rabbitmq':
  package_source => '',
  package_provider => 'yum',
  admin_enable => false,
}
