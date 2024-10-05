# frozen_string_literal: true

class TestModel
  include ActiveModel::Model

  attr_accessor :email

  validates :email, presence: true
  validates_with MailShield::SecureEmailValidator
end
