# frozen_string_literal: true

require_relative 'mailshield/version'
require_relative 'mailshield/disposable_domains'
require 'mailshield/secure_email_validator'
require 'resolv'
require 'csv'
require 'net/smtp'

module MailShield
  EMAIL_REGEX = /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/.freeze

  class ValidationError < StandardError; end
  class InvalidFormatError < ValidationError; end
  class DomainNotFoundError < ValidationError; end
  class SPFError < ValidationError; end
  class DMARCError < ValidationError; end
  class SMTPError < ValidationError; end
  class TemporaryDomainError < ValidationError; end
  class << self
    attr_accessor :dns_cache, :smtp_cache, :whitelist, :blacklist

    def configure
      @whitelist ||= []
      @blacklist ||= []
      yield self
    end

    def validate_email(email)
      reset_caches

      domain = extract_domain(email)

      return { valid: false, reason: 'Email domain is blacklisted.' } if blacklist.include?(domain)

      if !whitelist.empty? && !whitelist.include?(domain)
        return { valid: false, reason: 'Email domain is not whitelisted.' }
      end

      begin
        validate_known_disposal_domain?(domain)
        validate_format!(email)
        validate_domain!(domain)
        validate_spf!(domain)
        validate_dmarc!(domain)
        validate_smtp!(email)
      rescue ValidationError => e
        return { valid: false, reason: e.message }
      end

      { valid: true }
    end

    # Added Support for verifying email existance in real world
    def email_exists?(email)
      smtp_verify_email(email)
    end

    # Added Support for Email Format Validation
    def valid_format?(email)
      valid_email_format?(email)
    end

    private

    def reset_caches
      @dns_cache = {}
      @smtp_cache = {}
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

    def fetch_mx_records(domain)
      Resolv::DNS.open do |dns|
        dns.getresources(domain, Resolv::DNS::Resource::IN::MX).map(&:exchange).map(&:to_s)
      end
    rescue Resolv::ResolvError
      []
    end

    def spf_record?(domain)
      spf_records = fetch_txt_records(domain)
      spf_records.any? { |record| record.include?('v=spf1') }
    end

    def dmarc_record?(domain)
      dmarc_records = fetch_txt_records("_dmarc.#{domain}")
      dmarc_records.any? { |record| record.include?('v=DMARC1') }
    end

    def fetch_txt_records(domain)
      Resolv::DNS.open do |dns|
        records = dns.getresources(domain, Resolv::DNS::Resource::IN::TXT)
        records.map(&:data)
      end
    rescue Resolv::ResolvError
      []
    end

    def smtp_verify_email(email)
      domain = extract_domain(email)
      smtp_server = get_smtp_server(domain)

      return false unless smtp_server

      begin
        Net::SMTP.start(smtp_server, 25, 'localhost') do |smtp|
          smtp.helo('localhost')
          smtp.mailfrom('test@example.com')
          response = smtp.rcptto(email)
          response.status == '250' || response.status == '250 OK'
        end
      rescue Net::SMTPFatalError, Net::SMTPServerBusy, Net::SMTPSyntaxError, Errno::ECONNREFUSED
        false
      end
    end

    def get_smtp_server(domain)
      mx_records = fetch_mx_records(domain)
      mx_records.first
    end
  end
end

module ActiveModel
  module Validations
    class SecureEmailValidator < ::MailShield::SecureEmailValidator
      def initialize(options = {})
        super
      end
    end
  end
end
