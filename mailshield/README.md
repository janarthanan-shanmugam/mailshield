# MailShield

MailShield is a Ruby gem designed to detect temporary and disposable email domains. It helps secure applications by identifying and validating email domains, particularly those known for temporary email services.

## Features

- Identify known temporary email domains
- Validate email domains using DNS records (MX, SPF, DKIM, DMARC)
- Process email domains from a CSV file

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'mailshield'
```

Then execute:

bundle install
Or install it yourself with:

gem install mailshield

### Usage
Checking Single Email Domains

You can use MailShield to check if an email domain is temporary or disposable:
```ruby
require 'mailshield'

email = 'user@example.com'
if MailShield::DomainChecker.temporary_email?(email)
  puts "#{email} is a temporary or disposable email address."
else
  puts "#{email} is a valid email address."
end
```


## Contributing
Bug reports and pull requests are welcome on GitHub at https://github.com/yourusername/mailshield. You can also open an issue to discuss features or improvements.

### License
This gem is available as open source under the terms of the MIT License. See the LICENSE.txt file for details.

**Author**
JanarthananShanmugam
shanmugamjanarthan24@gmail.com
