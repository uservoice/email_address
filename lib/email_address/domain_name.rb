# frozen_string_literal: true

module EmailAddress

  # Provider takes a EmailAddress::User ingtance, determines the Email Service
  # Provider, and validates it to that provider. If the provider supports
  # address tags, these can be parsed off.

  class DomainName
    FORMATS = %i( default localhost ipv4 ipv6 subdomain fqdn )
    LEVELS = %i( default localhost ipv4 ipv6 subdomain fqdn )
    # default = Env Var of current email domain
    DEFAULTS = {
    }

    def initialize(user_email_address)
      @email_address = user_email_address
      @domain_name = user_email_address.domain_name
    end

  end

end

