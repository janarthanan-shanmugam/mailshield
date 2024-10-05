# spec/mailshield_spec.rb

require 'spec_helper'
require 'mailshield'
require_relative 'support/test_model' # Require the test model

RSpec.describe MailShield do
  
  describe '.validate_email' do
    context 'with a valid email' do
      context "when the email is not exist in real world" do 
        it 'returns valid: false' do
          result = MailShield.validate_email('user@gmail.com')
          expect(result[:valid]).to be false
        end
      end
      context "when the email is  exist in real world" do 
        it 'returns valid: true' do
          result = MailShield.validate_email('shanmugamjanarthan24@gmail.com')
          expect(result[:valid]).to be true
        end
      end
    end
    context 'with an invalid email format' do
      it 'returns valid: false and an invalid format error' do
        result = MailShield.validate_email('invalid-email')
        expect(result[:valid]).to be false
        expect(result[:reason]).to include('The email address format is invalid.')
      end
    end

    context 'with a non-existent domain' do
      it 'returns valid: false and a domain not found error' do
        result = MailShield.validate_email('user@nonexistentdomain.com')
        expect(result[:valid]).to be false
        expect(result[:reason]).to include('Email Not Found.')
      end
    end

    context 'with a temporary/disposable email' do
      it 'returns valid: false and an SPF error' do
        result = MailShield.validate_email('user@temporary.com')
        expect(result[:valid]).to be false
        expect(result[:reason]).to include('Temporary / Disposable Email.')
      end
    end
  end

  describe '.email_exists?' do
    context 'when SMTP verification is enabled' do
      it 'calls the smtp_verify_email method' do
        email = 'shanmugamjanarthan24@gmail.com'
        expect(MailShield).to receive(:smtp_verify_email).with(email).and_call_original
        result = MailShield.email_exists?(email)
        expect(result).to be true
      end
    end
  end

  describe '.known domains ' do
    context 'when address is known temprory domain ' do
      it 'calls the smtp_verify_email method' do
        email = 'user@10mail.org'
        result = MailShield.validate_email(email)
        expect(result[:valid]).to be false
        expect(result[:reason]).to eq('Temporary / Disposal Email.')
      end
    end
  end

  describe '.valid format' do
    context 'when the address is in in correct format' do
      it 'returns false' do
        email = '12121#3321%.com'
        result = MailShield.valid_format?(email)
        expect(result).to be false
      end
    end

    context 'when the address is in correct format' do
      it 'returns true' do
        email = 'user@example.com'
        result = MailShield.valid_format?(email)
        expect(result).to be true
      end
    end
  end


  describe 'SecureEmailValidator' do
    let(:model) { TestModel.new }
    
    context ".configure" do
      before(:each) do
        MailShield.configure do |config|
          config.whitelist = ['gmail.com', 'example.com']
          config.blacklist = ['spam.com']
        end
      end

      context 'when email is valid' do
        it 'is valid and passes through validation' do
          model.email = 'shanmugamjanarthan24@gmail.com' # Valid email
          expect(model.valid?).to be true
        end
      end

      context 'when email is blacklisted' do
        it 'adds an error for blacklisted domain' do
          model.email = 'user@spam.com'
          expect(model.valid?).to be false
          expect(model.errors.full_messages).to include('Email domain is blacklisted.')
        end
      end

      context 'when email domain is not whitelisted' do
        it 'adds an error for non-whitelisted domain' do
          model.email = 'user@nonwhitelisted.com'
          expect(model.valid?).to be false
          expect(model.errors.full_messages).to include('Email domain is not whitelisted.')
        end
      end
    end
  end
end
