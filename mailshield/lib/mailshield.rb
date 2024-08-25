# frozen_string_literal: true

require_relative "mailshield/version"
require 'resolv'

module MailShield
  class DomainChecker
    TEMP_DOMAINS = %w[mailinator.com tempmail.com guerrillamail.com].freeze # If any one want to contribute, please add the known more domains here.

    def self.temporary_email?(email)
      domain = extract_domain(email)
      return true if known_temp_domain?(domain)

      mx_records = fetch_mx_records(domain)
      return true if suspicious_mx_records?(mx_records)

      return true unless spf_record?(domain)
      return true unless dmarc_record?(domain)

      false
    end

    def self.extract_domain(email)
      email.split('@').last.downcase
    end

    def self.known_temp_domain?(domain)
      TEMP_DOMAINS.include?(domain)
    end

    def self.fetch_mx_records(domain)
      Resolv::DNS.open do |dns|
        mx_records = dns.getresources(domain, Resolv::DNS::Resource::IN::MX)
        mx_records.map(&:exchange).map(&:to_s)
      end
    rescue Resolv::ResolvError
      []
    end

    def self.suspicious_mx_records?(mx_records)
      suspicious_patterns = [/mailinator/, /tempmail/, /guerrillamail/]
      mx_records.any? { |mx| suspicious_patterns.any? { |pattern| mx.match?(pattern) } }
    end

    def self.spf_record?(domain)
      spf_records = fetch_txt_records(domain)
      spf_records.any? { |record| record.include?('v=spf1') }
    end

    def self.dmarc_record?(domain)
      dmarc_records = fetch_txt_records("_dmarc.#{domain}")
      dmarc_records.any? { |record| record.include?('v=DMARC1') }
    end

    def self.fetch_txt_records(domain)
      Resolv::DNS.open do |dns|
        records = dns.getresources(domain, Resolv::DNS::Resource::IN::TXT)
        records.map(&:data)
      end
    rescue Resolv::ResolvError
      []
    end
  end
end
