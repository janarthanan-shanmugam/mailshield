<h1 align="center">  MailShield </h1> 

<p align="center">
<img src="https://github.com/janarthanan-shanmugam/mailshield/blob/main/mailshield/lib/mailshield/docs/mailshield.png" alt="Description" width="300" style="border-radius: 52% !important;">
</p>

(An Advanced protective gem for securing your application from Spam, Disposal, Temporary Emails and validate the legitimacy of the emails.)
### Problem?
You are having a big application where daily n **number of users** creating account.

let say im a scammer and i **dont want to create an account with legitimate email address**,so i will go for some websites which will
provide some **temporary email address or disposal email address** which will be valid of **10 or 20 minutes**,
using that i will get the OTP and will create an account.

####
Storing the temproray or disposal email accounts in our database has no values in it, and also that user is not a legitimate one.

How to solve this issue? Here we have **_mailshield_**, we will protect you from all such things.
## Description

MailShield is a powerful and advanced validation/identification gem for Ruby on Rails, designed to protect your applications from **Disposable**, **Temporary**, **fake** , **Spam**
and **non existance** email addresses. 

It performs DNS, SPF, MF, DMARK,DNSBL  record checks along with SMTP verification to ensure that email addresses are legitimate and secure, helping you maintain the integrity of your user data.


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

## NUMBER OF VALIDATIONS PERFORMED:
1. DMARK
2. SPF
3. Reverse DNS
4. DNS blacklisted Domains (DNSBL)
5. DNS TXT
6. Spam Domains
7. Domain Age
8. Email Existance in the Real world.

all these validations will be performed with short span less 20 ms
<br>
## 
Also you can use our some of seperate methods for performing individual verification aswell like:- 
1. validate_email (will perform all kind of validation mentioned above)
2. email_exits? (this will verify whether that particular email address is exists or not.)
   
## 

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

<br>

### Note: All these validations will be performed, by just adding secure_email: true in your model as mentioned above.

## 
### Custom Configurations / Whitelisted domain or Black listed domains on custom configuration
Here’s an example of how to configure the MailShield gem with a whitelist and a blacklist:

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

so when you try to save the record, it will validate the black listed as well as white listed domains along with other validations.      

------------------------------------------------------------------------------------------

Feel free to open an issue or submit a pull request on GitHub.

### License
This gem is available as open-source under the terms of the MIT License.

#### For any queries or clarification, Contact @shanmugamjanarthan24@gmail.com (JANSHA)
