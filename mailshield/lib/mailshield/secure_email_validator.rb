require 'active_model'

module MailShield
  class SecureEmailValidator < ActiveModel::Validator
    def validate(record)
      email = record.email
      return if email.blank?

      result = MailShield.validate_email(email)

      unless result[:valid]
        record.errors.add(:email, result[:issue])
      end
    end
  end
end
