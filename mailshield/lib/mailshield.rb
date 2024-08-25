# frozen_string_literal: true

require_relative "mailshield/version"
require 'resolv'
require 'csv'

module MailShield

  class ValidationResult
    attr_reader :emails

    def initialize(emails)
      @emails = emails
    end

    def valid_emails
      emails.select { |email| email[:valid] }.map { |email| email[:email] }
    end

    def invalid_emails
      emails.reject { |email| email[:valid] }.map { |email| email[:email] }
    end

    def get_emails
      emails.map { |email| { email: email[:email], valid: email[:valid] } }
    end
  end

  class << self
    TEMP_DOMAINS = %w[mailinator.com tempmail.com guerrillamail.com].freeze # Known temporary domains


    # Main method to validate an email and return results in a hash
    def validate_email(email)
      result = {
        email: email,
        valid: true,
        issues: []
      }

      unless valid_email_format?(email)
        result[:valid] = false
        result[:issues] << "The email address format is invalid."
        return result
      end

      domain = extract_domain(email)

      if known_temp_domain?(domain)
        result[:valid] = false
        result[:issues] << "The email domain is known to be temporary or disposable."
        return result
      end

      mx_records = fetch_mx_records(domain)
      if mx_records.empty?
        result[:valid] = false
        result[:issues] << "The email domain does not have valid mail exchange records."
        return result
      elsif suspicious_mx_records?(mx_records)
        result[:valid] = false
        result[:issues] << "The email domain's mail exchange records suggest it might be used for temporary or disposable email services."
        return result
      end

      unless spf_record?(domain)
        result[:valid] = false
        result[:issues] << "The email domain is missing important records that help confirm its authenticity."
        return result
      end

      unless dmarc_record?(domain)
        result[:valid] = false
        result[:issues] << "The email domain is missing records that help protect against email fraud."
        return result
      end

      result
    end

    def validate_emails_from_csv(input_file_path)
      email_results = []

      CSV.foreach(input_file_path, headers: true) do |row|
        email = row['email']
        validation_result = validate_email_for_csv(email)
        email_results << { email: email, valid: validation_result }
      end

      ValidationResult.new(email_results)
    end

    def validate_email_for_csv(email)
      return false unless valid_email_format?(email)
      domain = extract_domain(email)

      return false if known_temp_domain?(domain)
      return false unless spf_record?(domain)
      return false unless dmarc_record?(domain)

      true
    end

    private

    def extract_domain(email)
      email.split('@').last.downcase
    end

    def valid_email_format?(email)
      email_regex = /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/
      !!(email =~ email_regex)
    end

    def known_temp_domain?(domain)
      TEMP_DOMAINS.include?(domain)
    end

    def fetch_mx_records(domain)
      Resolv::DNS.open do |dns|
        mx_records = dns.getresources(domain, Resolv::DNS::Resource::IN::MX)
        mx_records.map(&:exchange).map(&:to_s)
      end
    rescue Resolv::ResolvError
      []
    end

    def suspicious_mx_records?(mx_records)
      suspicious_patterns = [/mailinator/, /tempmail/, /guerrillamail/]
      mx_records.any? { |mx| suspicious_patterns.any? { |pattern| mx.match?(pattern) } }
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
  end
end


# SPF Record Explanation:
#
# SPF (Sender Policy Framework): A mechanism that helps email servers verify that an email claiming to come from a specific domain is actually sent by an authorized mail server. 
# This prevents spammers from sending messages with forged "From" addresses.
#
# DMARC Record Explanation:
#
# DMARC (Domain-based Message Authentication, Reporting, and Conformance): A protocol that builds on SPF and DKIM (DomainKeys Identified Mail) to help email domain owners protect their domain from being used in email spoofing. 
# It provides a way for domain owners to publish policies about their email authentication practices and how receiving mail servers should enforce them.
#
# References:
# https://www.dkim.org/
# https://www.cloudflare.com/en-gb/learning/dns/dns-records/dns-spf-record/