# frozen_string_literal: true

# EmailAddress parses and validates email addresses against RFC standard,
# conventional, canonical, formats and other special uses.
#
# Email Address Subtypes:
#   * Standard: RFC-2822 Compliant
#   * Loose: A simple validator, nothing complex, not too rigid
#   * Conventional: General format of in-use addresses, superceded by provider
#   * Canonical: General format, simplified, no tags
#   * Digest: MD5 of input address
#   * Redacted: Changed to a fingerprint, {DIGEST}@domain.tld
#   * Munged: Obscured for online hiding, a***@g***.com
#   * SRS, PVRS, BATV: Forms for encoding in sending domain formats
#   * VERP: Return Path version (from Qmail)
#
# General Usage:
#
#     emailaddr = EmailAddress.standard(email_address_string, config_override: "value")
#     emailaddr.valid?
#     EmailAddress.canonical(email_address_string).valid?
#     EmailAddress.valid?(email_address_string)
#     EmailAddress.new(email_address_string).redact!
#
module EmailAddress

  require "email_address/config"
  #require "email_address/exchanger"
  require "email_address/domain"
  require "email_address/local"
  require "email_address/provider"
  require "email_address/rewriter"
  require "email_address/address"
  require "email_address/dns"
  require "email_address/version"

  require "email_address/active_record_validator" if defined?(ActiveModel)
  if defined?(ActiveRecord) && ::ActiveRecord::VERSION::MAJOR >= 5
    require "email_address/email_address_type"
    require "email_address/canonical_email_address_type"
  end

  # @!method self.valid?(email_address, options={})
  #   Proxy method to {EmailAddress::Address#valid?}
  # @!method self.error(email_address)
  #   Proxy method to {EmailAddress::Address#error}
  # @!method self.normal(email_address)
  #   Proxy method to {EmailAddress::Address#normal}
  # @!method self.redact(email_address, options={})
  #   Proxy method to {EmailAddress::Address#redact}
  # @!method self.munge(email_address, options={})
  #   Proxy method to {EmailAddress::Address#munge}
  # @!method self.base(email_address, options{})
  #   Returns the base form of the email address, the mailbox
  #   without optional puncuation removed, no tag, and the host name.
  # @!method self.canonical(email_address, options{})
  #   Proxy method to {EmailAddress::Address#canonical}
  # @!method self.reference(email_address, form=:base, options={})
  #   Returns the reference form of the email address, by default
  #   the MD5 digest of the Base Form the the address.
  # @!method self.srs(email_address, sending_domain, options={})
  #   Returns the address encoded for SRS forwarding. Pass a local
  #   secret to use in options[:secret]
  class << self
    (%i[valid? error normal redact munge canonical reference base srs ] &
     EmailAddress::Address.public_instance_methods
    ).each do |proxy_method|
      define_method(proxy_method) do |*args, &block|
        EmailAddress::Address.new(*args).public_send(proxy_method, &block)
      end
    end
  end


  # Creates an instance of this email address.
  # This is a short-cut to Email::Address::Address.new
  def self.new(email_address, config={})
    EmailAddress::Address.new(email_address, config)
  end

  def self.new_redacted(email_address, config={})
    EmailAddress::Address.new(EmailAddress::Address.new(email_address, config).redact)
  end

  def self.new_canonical(email_address, config={})
    EmailAddress::Address.new(EmailAddress::Address.new(email_address, config).canonical, config)
  end

  # Does the email address match any of the given rules
  def self.matches?(email_address, rules, config={})
    EmailAddress::Address.new(email_address, config).matches?(rules)
  end
end
