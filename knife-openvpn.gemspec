# -*- encoding: utf-8 -*-
$LOAD_PATH.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |gem|
  gem.name        = 'knife-openvpn'
  gem.version     = '0.0.5'
  gem.summary     = 'A knife plugin for Express 42 openvpn cookbook'
  gem.description = gem.summary
  gem.authors     = ['LLC Express 42']
  gem.email       = 'cookbooks@express42.com'
  gem.homepage    = 'https://github.com/express42/knife-openvpn'
  gem.license     = 'MIT'

  gem.files         = `git ls-files`.split("\n")
  gem.require_paths = ['lib']
end
