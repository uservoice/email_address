# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'email_address/version'

Gem::Specification.new do |spec|
  spec.name          = 'email_address'
  spec.version       = EmailAddress::VERSION
  spec.authors       = ['Allen Fair']
  spec.email         = ['allen.fair@gmail.com']
  spec.description   = <<-DESCRIPTION
  The EmailAddress Gem to introspect and validate email addresses using rules
  from major email service providers.
  DESCRIPTION
  spec.summary = <<-SUMMARY
  This gem provides a ruby language library for working with and validating
  email addresses. By default, it defines address level to target RFC-Standard
  to user email addresses.
  SUMMARY
  spec.homepage      = 'https://github.com/afair/email_address'
  spec.license       = 'MIT'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'simpleidn'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'irb'
  spec.add_development_dependency 'minitest'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake'
  if RUBY_PLATFORM == 'java'
    spec.add_development_dependency 'activerecord', '=  5.2.0'
    spec.add_development_dependency 'activerecord-jdbcsqlite3-adapter', '~> 1.3.24'
  else
    spec.add_development_dependency 'activerecord', '~> 6.0.0'
    spec.add_development_dependency 'sqlite3'
  end
  spec.add_development_dependency 'simplecov'
end
