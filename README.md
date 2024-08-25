# MailShield

**MailShield** is a Ruby gem designed to help you identify and validate email domains. It detects temporary, disposable email domains, verifies proper DNS records (SPF, DKIM, DMARC), and ensures email format validity. This gem is particularly useful for securing your application by filtering out invalid or suspicious email addresses.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'mailshield'
```

And then execute:

```ruby
bundle install

```

Or install it yourself as:

```ruby
gem install mailshield

```


## Usage
### Basic Email Validation
You can validate whether an email domain is legitimate, temporary, or suspicious with a single method:


```ruby 
result = MailShield.validate_email('user@example.com')
puts result[:valid]          # => true or false
puts result[:issues]         # => reason for the email to be a temprorary or scam email 


```

### CSV Email Validation
If you have a list of email domains in a CSV file, you can validate them and get a report:

```ruby 

result = MailShield.validate_csv('path/to/emails.csv')

puts result.emails           # => List of all emails with their validation status
puts result.valid_emails     # => List of valid emails
puts result.invalid_emails   # => List of invalid emails


```

### Example CSV Output
Here’s what you can expect in the CSV output:

```ruby
Email, Valid
user@example.com, true
fake@mailinator.com, false

```

### Methods Overview

MailShield.validate_email(email)

Returns a hash with the validation status and any issues found.

MailShield.validate_csv(csv_path)
* Returns an object containing methods to access:
   * * ll emails with their validation status.
   * * Valid emails only.
   * * Invalid emails only.


### Email Validation Checks
Temporary Email Detection:

Checks against a known list of temporary email domains.
Inspects MX records for suspicious patterns.
DNS Record Verification:

SPF Record: Verifies if the domain has a Sender Policy Framework (SPF) record.
DMARC Record: Checks for the presence of a DMARC record.
DKIM Record: Ensures that the domain is configured with DomainKeys Identified Mail (DKIM).
Email Format Validation:

Ensures the email address follows standard format conventions.
Example Validation Process
For example, if you validate user@mailinator.com, MailShield will:

Detect that mailinator.com is a known temporary domain.
Check the MX records for suspicious patterns.
Verify the presence of SPF and DMARC records.
Validate the email format.

```ruby
{
  valid: false,
  issues: ["The domain is associated with a temporary email provider."]
}
```

We welcome contributions to the list of known temporary domains or any other improvements to the gem. Feel free to open an issue or submit a pull request on GitHub.

### License
This gem is available as open-source under the terms of the MIT License.

References
SPF: Introduction
DKIM Overview
DMARC Overview
