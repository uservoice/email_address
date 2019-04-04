# frozen_string_literal: true

module EmailAddress

  # Provider takes a EmailAddress::User ingtance, determines the Email Service
  # Provider, and validates it to that provider. If the provider supports
  # address tags, these can be parsed off.

  class Provider

    def initialize(user_email_address)
      @email_address = user_email_address
    end

  end

end

