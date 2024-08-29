# frozen_string_literal: true

require_relative 'mailshield/version'
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

  class << self
    attr_accessor :dns_cache, :smtp_cache

    def validate_email(email, verify_by_send: false)
      reset_caches

      domain = extract_domain(email)

      begin
        validate_format!(email)
        validate_domain!(domain)
        validate_spf!(domain)
        validate_dmarc!(domain)
        validate_smtp!(email) if verify_by_send
      rescue ValidationError => e
        return { valid: false, issues: [e.message] }
      end

      { valid: true, issues: [] }
    end


    def verify_address(email)
      smtp_verify_email(email)
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
      raise SPFError, 'Temporary / Disposable Email' unless spf_record?(domain)
    end

    def validate_dmarc!(domain)
      raise DMARCError, 'Temporary / Disposable Email' unless dmarc_record?(domain)
    end

    def validate_smtp!(email)
      raise SMTPError, 'Email Address Not Found' unless smtp_verify_email(email)
    end

    def extract_domain(email)
      email.split('@').last.downcase
    end

    def valid_email_format?(email)
      EMAIL_REGEX.match?(email)
    end

    def fetch_mx_records(domain)
      dns_cache[domain] ||= begin
        Resolv::DNS.open do |dns|
          dns.getresources(domain, Resolv::DNS::Resource::IN::MX).map(&:exchange).map(&:to_s)
        end
      rescue Resolv::ResolvError
        []
      end
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
      dns_cache[domain] ||= begin
        Resolv::DNS.open do |dns|
          dns.getresources(domain, Resolv::DNS::Resource::IN::TXT).map(&:data)
        end
      rescue Resolv::ResolvError
        []
      end
    end

    def smtp_verify_email(email)
      domain = extract_domain(email)
      smtp_server = smtp_cache[domain] ||= get_smtp_server(domain)

      return false unless smtp_server

      begin
        Net::SMTP.start(smtp_server, 25, 'localhost') do |smtp|
          smtp.helo('localhost')
          smtp.mailfrom('test@example.com')
          response = smtp.rcptto(email)
          response == '250 OK'
        end
      rescue Net::SMTPFatalError, Net::SMTPServerBusy, Net::SMTPSyntaxError, Errno::ECONNREFUSED => e
        false
      end
    end

    def get_smtp_server(domain)
      mx_records = fetch_mx_records(domain)
      mx_records.first
    end
  end
end
