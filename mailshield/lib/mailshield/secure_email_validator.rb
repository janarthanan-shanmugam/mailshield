# frozen_string_literal: true

require 'active_model'

module MailShield
  class SecureEmailValidator < ActiveModel::Validator
    def validate(record)
      email = record.email
      return if email.blank?

      result = MailShield.validate_email(email)

      return if result[:valid]

      record.errors.add(:base, result[:reason])
    end
  end
end
