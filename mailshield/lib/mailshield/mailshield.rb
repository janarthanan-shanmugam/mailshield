# frozen_string_literal: true

require_relative 'mailshield/version'
require_relative 'mailshield/disposable_domains'
require 'mailshield/secure_email_validator'
require 'resolv'
require 'csv'
require 'net/smtp'

module MailShield
  # Regex pattern for validating email formats
  EMAIL_REGEX = /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/.freeze

  # Custom error classes for various validation failures
  class ValidationError < StandardError; end
  class InvalidFormatError < ValidationError; end
  class DomainNotFoundError < ValidationError; end
  class SPFError < ValidationError; end
  class DMARCError < ValidationError; end
  class SMTPError < ValidationError; end
  class TemporaryDomainError < ValidationError; end
  
  class << self
    attr_accessor :dns_cache, :smtp_cache, :whitelist, :blacklist

    # Configuration method for initializing and yielding settings
    def configure
      initialize_lists
      yield self if block_given?
    end

    # Validate the structure and existence of the provided email
    def validate_email(email)
      reset_caches
      domain = extract_domain(email)

      return { valid: false, reason: 'Email domain is blacklisted.' } if blacklist && blacklist.include?(domain)

      if whitelist && !whitelist.empty? && !whitelist.include?(domain)
        return { valid: false, reason: 'Email domain is not whitelisted.' }
      end

      # Perform comprehensive validation checks
      perform_validations(email, domain)
    end

    def email_exists?(email)
      smtp_verify_email(email)
    end

    def valid_format?(email)
      valid_email_format?(email)
    end

    private

    # Initialize lists for whitelisting and blacklisting
    def initialize_lists
      @whitelist ||= []
      @blacklist ||= []
    end

    def reset_caches
      @dns_cache = {}
      @smtp_cache = {}
    end

    def blacklisted?(domain)
      blacklist.include?(domain)
    end

    def handle_blacklist(domain)
      {
        valid: false,
        reason: 'Email domain is blacklisted.'
      }
    end

    def whitelisted?(domain)
      !whitelist.empty? && whitelist.include?(domain)
    end

    def handle_whitelist(domain)
      {
        valid: false,
        reason: 'Email domain is not whitelisted.'
      }
    end

    # Perform all necessary validations for the given email
    def perform_validations(email, domain)
      begin
        validate_known_disposal_domain?(domain) # Custom method to check for disposable domains
        validate_format!(email)
        validate_domain!(domain)
        validate_spf!(domain)
        validate_dmarc!(domain)
        validate_smtp!(email)
      rescue ValidationError => e
        return handle_validation_error(e)
      end

      { valid: true }
    end

    def handle_validation_error(error)
      { valid: false, reason: error.message }
    end

    def validate_format!(email)
      raise InvalidFormatError, 'The email address format is invalid.' unless valid_email_format?(email)
    end

    def validate_domain!(domain)
      raise DomainNotFoundError, 'Email Not Found.' if fetch_mx_records(domain).empty?
    end

    def validate_spf!(domain)
      raise SPFError, 'Temporary / Disposable Email.' unless spf_record?(domain)
    end

    def validate_dmarc!(domain)
      raise DMARCError, 'Temporary / Disposable Email.' unless dmarc_record?(domain)
    end

    def validate_smtp!(email)
      raise SMTPError, 'Email Address Not Found.' unless smtp_verify_email(email)
    end

    def extract_domain(email)
      email.split('@').last.downcase
    end

    def valid_email_format?(email)
      EMAIL_REGEX.match?(email)
    end

    # Fetch MX records for the given domain
    def fetch_mx_records(domain)
      Resolv::DNS.open do |dns|
        dns.getresources(domain, Resolv::DNS::Resource::IN::MX).map(&:exchange).map(&:to_s)
      end
    rescue Resolv::ResolvError
      []
    end

    # Check if SPF records are available for the domain
    def spf_record?(domain)
      spf_records = fetch_txt_records(domain)
      spf_records.any? { |record| record.include?('v=spf1') }
    end

    # Check if DMARC records are available for the domain
    def dmarc_record?(domain)
      dmarc_records = fetch_txt_records("_dmarc.#{domain}")
      dmarc_records.any? { |record| record.include?('v=DMARC1') }
    end

    # Fetch TXT records for the domain
    def fetch_txt_records(domain)
      Resolv::DNS.open do |dns|
        records = dns.getresources(domain, Resolv::DNS::Resource::IN::TXT)
        records.map(&:data)
      end
    rescue Resolv::ResolvError
      []
    end

    # Verify the email address using SMTP
    def smtp_verify_email(email)
      domain = extract_domain(email)
      smtp_server = get_smtp_server(domain)

      return false unless smtp_server

      begin
        Net::SMTP.start(smtp_server, 25, 'localhost') do |smtp|
          smtp.helo('localhost')
          smtp.mailfrom('test@example.com')
          response = smtp.rcptto(email)
          smtp_response_status(response)
        end
      rescue Net::SMTPFatalError, Net::SMTPServerBusy, Net::SMTPSyntaxError, Errno::ECONNREFUSED
        false
      end
    end

    def smtp_response_status(response)
      response.status == '250' || response.status == '250 OK'
    end

    # Retrieve the SMTP server for the specified domain
    def get_smtp_server(domain)
      mx_records = fetch_mx_records(domain)
      mx_records.first
    end
  end
end

module ActiveModel
  module Validations
    # Validator for secure email verification
    class SecureEmailValidator < ::MailShield::SecureEmailValidator
      def initialize(options = {})
        super
      end
    end
  end
end
