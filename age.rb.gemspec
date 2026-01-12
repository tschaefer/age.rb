# frozen_string_literal: true

$LOAD_PATH << File.expand_path('lib', __dir__)
require 'age/version'

Gem::Specification.new do |spec|
  spec.name        = 'age.rb'
  spec.version     = Age::VERSION
  spec.platform    = Gem::Platform::RUBY
  spec.authors     = ['Tobias Schäfer']
  spec.email       = ['github@blackox.org']

  spec.summary     = 'age.rb: Ruby bindings for age'
  spec.description = <<~DESC
    #{spec.summary}
  DESC
  spec.homepage    = 'https://github.com/tschaefer/age.rb'
  spec.license     = 'BSD-3-Clause'

  spec.files                 = Dir['lib/**/*', 'ext/**/*']
  spec.extensions            = ['ext/extconf.rb']
  spec.require_paths         = ['lib']
  spec.required_ruby_version = '>= 3.2.3'

  spec.metadata['rubygems_mfa_required'] = 'true'
  spec.metadata['source_code_uri']       = 'https://github.com/tschaefer/age.rb'
  spec.metadata['bug_tracker_uri']       = 'https://github.com/tschaefer/age.rb/issues'

  spec.add_dependency 'ffi', '~> 1.17'
end
