# frozen_string_literal: true

# AfairEmailAddress parses and validates email addresses against RFC standard,
# conventional, canonical, formats and other special uses.
module AfairEmailAddress

  require "afair_email_address/config"
  require "afair_email_address/exchanger"
  require "afair_email_address/host"
  require "afair_email_address/local"
  require "afair_email_address/rewriter"
  require "afair_email_address/address"
  require "afair_email_address/version"
  require "afair_email_address/active_record_validator" if defined?(ActiveModel)
  if defined?(ActiveRecord) && ::ActiveRecord::VERSION::MAJOR >= 5
    require "afair_email_address/email_address_type"
    require "afair_email_address/canonical_email_address_type"
  end

  # @!method self.valid?(email_address, options={})
  #   Proxy method to {AfairEmailAddress::Address#valid?}
  # @!method self.error(email_address)
  #   Proxy method to {AfairEmailAddress::Address#error}
  # @!method self.normal(email_address)
  #   Proxy method to {AfairEmailAddress::Address#normal}
  # @!method self.redact(email_address, options={})
  #   Proxy method to {AfairEmailAddress::Address#redact}
  # @!method self.munge(email_address, options={})
  #   Proxy method to {AfairEmailAddress::Address#munge}
  # @!method self.base(email_address, options{})
  #   Returns the base form of the email address, the mailbox
  #   without optional puncuation removed, no tag, and the host name.
  # @!method self.canonical(email_address, options{})
  #   Proxy method to {AfairEmailAddress::Address#canonical}
  # @!method self.reference(email_address, form=:base, options={})
  #   Returns the reference form of the email address, by default
  #   the MD5 digest of the Base Form the the address.
  # @!method self.srs(email_address, sending_domain, options={})
  #   Returns the address encoded for SRS forwarding. Pass a local
  #   secret to use in options[:secret]
  class << self
    (%i[valid? error normal redact munge canonical reference base srs] &
     AfairEmailAddress::Address.public_instance_methods
    ).each do |proxy_method|
      define_method(proxy_method) do |*args, &block|
        AfairEmailAddress::Address.new(*args).public_send(proxy_method, &block)
      end
    end
  end


  # Creates an instance of this email address.
  # This is a short-cut to Email::Address::Address.new
  def self.new(email_address, config={})
    AfairEmailAddress::Address.new(email_address, config)
  end

  def self.new_redacted(email_address, config={})
    AfairEmailAddress::Address.new(AfairEmailAddress::Address.new(email_address, config).redact)
  end

  def self.new_canonical(email_address, config={})
    AfairEmailAddress::Address.new(AfairEmailAddress::Address.new(email_address, config).canonical, config)
  end

  # Does the email address match any of the given rules
  def self.matches?(email_address, rules, config={})
    AfairEmailAddress::Address.new(email_address, config).matches?(rules)
  end
end
