<h1 align="center">  MailShield </h1> 

<p align="center">
<img src="https://github.com/janarthanan-shanmugam/mailshield/blob/main/mailshield/lib/mailshield/docs/mailshield.png" alt="Description" width="300" style="border-radius: 52% !important;">
</p>

(An Advanced protective gem for securing your application from Spam, Disposal, Temporary Emails and validate the legitimacy of the emails.)

## Description

MailShield is a powerful and flexible email validation gem for Ruby on Rails, designed to protect your applications from **Disposable**, **Temporary**, **fake** 
and **non existance** email addresses. 

It performs DNS record checks along with SMTP verification to ensure that email addresses are legitimate and secure, helping you maintain the integrity of your user data.


**Ensure the authenticity and security of email addresses in your Ruby on Rails applications with MailShield.**


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
use _**secure_email: true**_

Whenever a record being saved with invalid, spam or disposal email or no such email exists, then this will validate that and return validation error.

### Email Validation Features
You can validate whether an email domain is legitimate, temporary, or suspicious with a single option:


```ruby 
result = MailShield.validate_email('user@example.com')
puts result[:valid]          # => true or false
puts result[:reason]         # => if valid false, then reason.


```


### Also you can validate whether a given email address is exist in the real world or not .
```ruby 

 MailShield.email_exists?('example@example.com')

**RESULT:**
true // if email exists in real world.
false // if no such email present in the real world.
  
```
this will verify whether that particular email address is exists or not.

### Whitelisted domain or Black listed domains on custom configuration

create a initializer file for the mailshield 

```ruby 
# config/initializers/mailshield.rb

MailShield.configure do |config|
  # Define a whitelist of allowed email domains
  config.whitelist = ['example.com', 'trustedsite.org']

  # Define a blacklist of disallowed email domains
  config.blacklist = ['tempmail.com', 'spamdomain.com']
end

```

so when you try to save the record, it will validate the black listed as well as white listed domains.


------------------------------------------------------------------------------------------

Feel free to open an issue or submit a pull request on GitHub.

### License
This gem is available as open-source under the terms of the MIT License.

#### For any queries or clarification, Contact @shanmugamjanarthan24@gmail.com (JANSHA)
