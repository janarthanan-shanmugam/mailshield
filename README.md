<h1 align="center">  MailShield </h1> 

<p align="center">
<img src="https://github.com/janarthanan-shanmugam/mailshield/blob/main/mailshield/lib/mailshield/docs/mailshield.png" alt="Description" width="300" style="border-radius: 52% !important;">
</p>

(An Advanced protective gem for securing your application from Spam, Disposal, Temporary Emails and validate the legitimacy of the emails.)

## Description

MailShield is a powerful and flexible email validation gem for Ruby on Rails, designed to protect your applications from disposable, temporary, and invalid email addresses. 

It leverages DNS record checks (MX, SPF, DMARC) and optional SMTP verification to ensure that email addresses are legitimate and secure, helping you maintain the integrity of your user data.


Ensure the authenticity and security of email addresses in your Ruby on Rails applications with MailShield. 

This comprehensive gem offers advanced email validation through DNS record checks (MX, SPF, DMARC) and optional SMTP verification.
MailShield helps prevent the use of disposable and fake email addresses, safeguarding your platform from spam and enhancing data quality.
Ideal for developers seeking to strengthen email verification in their applications.

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

###  Model Integration
With MailShield, you can easily add email validation to your Rails models using the secure_email validator. Simply include it in your model like this:

```ruby

# app/models/user.rb
class User < ApplicationRecord
  validates :email, secure_email: true
end
```

This will secure the email and throw an validation error if it is a spam email or disposal email or temproary email or invalid email.

### Email Validation Features
You can validate whether an email domain is legitimate, temporary, or suspicious with a single method:


```ruby 
result = MailShield.validate_email('user@example.com')
puts result[:valid]          # => true or false
puts result[:issues]         # => reason for the email to be a temprorary or scam email 


```
The verify_by_send: true option in the MailShield gem enables a feature that performs additional verification of the email address using the SMTP protocol. Here’s a detailed explanation:


```ruby 

result = MailShield.validate_email('example@example.com', verify_by_send: true)

```


**What is verify_by_send: true?**

When you set verify_by_send: true, the MailShield gem will attempt to connect to the email domain’s mail server using SMTP (Simple Mail Transfer Protocol) to further verify the validity of the email address. 

This process does not send an actual email but checks if the mail server would accept the email address.

default to false -> refers this validaiton wont be occured.


### also you can perform the specific validation aswell

if MailShield.verify_address('example@example.com')
  returns true if the email is not spam and it is a legitiamate email 
else
  return false if the email found to be a spam or non legitimate emails
end


------------------------------------------------------------------------------------------

Feel free to open an issue or submit a pull request on GitHub.

### License
This gem is available as open-source under the terms of the MIT License.

References
SPF: Introduction
DKIM Overview
DMARC Overview
