# frozen_string_literal: true

require_relative "lib/mailshield/version"

Gem::Specification.new do |spec|
  spec.name = "mailshield"
  spec.version = Mailshield::VERSION
  spec.authors = ["jana"]
  spec.email = ["shanmugamjanarthan24@gmail.com"]

  spec.summary = "A gem to detect temporary or disposable email domains."
  spec.description = "MailShield helps secure your application by identifying temporary or disposable email domains."
  spec.homepage = "https://github.com/janarthanan-shanmugam/mailshield"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.0.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/janarthanan-shanmugam/mailshield"
  spec.metadata["changelog_uri"] = "https://github.com/janarthanan-shanmugam/mailshield"

  spec.files         = Dir["lib/**/*"]
  spec.require_paths = ["lib"]

   spec.required_ruby_version = ">= 2.5"


  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end

