# frozen_string_literal: true

require 'yaml'

# Email Address Gem
module EmailAddress
  # Email Address Configuration Manager.
  #
  # Usage:
  #   # Override defaults in your application:
  #   EmailAddress::Config.defaults[:local_fix] = true
  #
  #   # Create a local email provider with special rules:
  #   EmailAddress::Config.providers[:x] = {override_name: value, ...}
  #
  #   config = EmailAddress::Config.new(override_name: value, ...)
  #   config[:setting]
  #
  # * dns_lookup:         :mx, :a, :off
  #   Enables DNS lookup for validation by
  #   :mx       - DNS MX Record lookup
  #   :a        - DNS A Record lookup (allow badly configured MX domains)
  #   :off      - Do not perform DNS lookup (Test mode, network unavailable)
  #
  # * sha1_secret         ""
  #   This application-level secret is appended to the email_address to compute
  #   the SHA1 Digest, making it unique to your application so it can't easily
  #   be discovered by comparing against a known list of email/sha1 pairs.
  #
  # For local part configuration:
  # * local_downcase:     true
  #   Downcase the local part. You probably want this for uniqueness.
  #   RFC says local part is case insensitive, that's a bad part.
  #
  # * local_fix:          true,
  #   Make simple fixes when available, remove spaces, punctuations
  #
  # * local_encoding:     :ascii, :unicode,
  #   Enable Unicode in local part. Most mail systems do not yet support this.
  #   You probably want to stay with ASCII for now.
  #
  # * local_parse:        nil, ->(local) { [mailbox, tag, comment] }
  #   Specify an optional lambda/Proc to parse the local part. It should return
  #   an array (tuple) of mailbox, tag, and comment.
  #
  # * local_format:       :conventional, :relaxed, :redacted, :standard, Proc
  #   :conventional       word ( puncuation{1} word )*
  #   :relaxed            alphanum ( allowed_characters)* alphanum
  #   :standard           RFC Compliant email addresses (anything goes!)
  #
  # * local_size:         1..64,
  #   A Range specifying the allowed size for mailbox + tags + comment
  #
  # * tag_separator:      nil, character (+)
  #   Nil, or a character used to split the tag from the mailbox
  #
  # For the mailbox (AKA account, role), without the tag
  # * mailbox_size:       1..64
  #   A Range specifying the allowed size for mailbox
  #
  # * mailbox_canonical:  nil, ->(mailbox) { mailbox }
  #   An optional lambda/Proc taking a mailbox name, returning a canonical
  #   version of it. (E.G.: gmail removes '.' characters)
  #
  # * mailbox_validator:  nil, ->(mailbox) { true }
  #   An optional lambda/Proc taking a mailbox name, returning true or false.
  #
  # * host_encoding:      :punycode,  :unicode,
  #   How to treat International Domain Names (IDN). Note that most mail and
  #   DNS systems do not support unicode, so punycode needs to be passed.
  #   :punycode           Convert Unicode names to punycode representation
  #   :unicode            Keep Unicode names as is.
  #
  # * host_validation:
  #   :mx                 Ensure host is configured with DNS MX records
  #   :a                  Ensure host is known to DNS (A Record)
  #   :syntax             Validate by syntax only, no Network verification
  #   :connect            Attempt host connection (not implemented, BAD!)
  #
  # * host_size:          1..253,
  #   A range specifying the size limit of the host part,
  #
  # * host_allow_ip:      false,
  #   Allow IP address format in host: [127.0.0.1], [IPv6:::1]
  #
  # * host_local:         false,
  #   Allow localhost, no domain, or local subdomains.
  #
  # * address_validation: :parts, :smtp, ->(address) { true }
  #   Address validation policy
  #   :parts              Validate local and host.
  #   :smtp               Validate via SMTP (not implemented, BAD!)
  #   A lambda/Proc taking the address string, returning true or false
  #
  # * address_size:       3..254,
  #   A range specifying the size limit of the complete address
  #
  # * address_fqdn_domain: nil || "domain.tld"
  #   Configure to complete the FQDN (Fully Qualified Domain Name)
  #   When host is blank, this value is used
  #   When host is computer name only, this is appended to get the FQDN
  #   You probably don't want this unless you have host-local email accounts
  #
  # For provider rules to match to domain names and Exchanger hosts
  # The value is an array of match tokens.
  # * host_match:         %w(.org example.com hotmail. user*@ sub.*.com)
  # * exchanger_match:    %w(google.com 127.0.0.1 10.9.8.0/24 ::1/64)
  #
  class Config
    class << self
      attr_accessor :defaults, :providers, :error_messages
    end

    ############################################################################
    # Data
    ############################################################################

    @defaults = {
      dns_lookup: :mx, # :mx, :a, :off
      dns_cache: :no, # :file, Proc
      sha1_secret: '',
      munge_string: '*****',

      local_downcase: true,
      local_fix: false,
      local_encoding: :ascii, # :ascii, :unicode,
      local_parse: nil, # nil, Proc
      local_format: :conventional, # or: :relaxed, :redacted, :standard, Proc
      local_size: 1..64,
      tag_separator: '+', # nil, character
      mailbox_size: 1..64, # without tag
      mailbox_canonical: nil, # nil,  Proc
      mailbox_validator: nil, # nil,  Proc

      host_encoding: :punycode || :unicode,
      host_validation: :mx, # :a || :connect || :syntax,
      host_size: 1..253,
      host_allow_ip: false,
      host_remove_spaces: false,
      host_local: false,

      address_validation: :parts, # :parts, :smtp, Proc
      address_size: 3..254,
      address_fqdn_domain: nil # Fully Qualified Domain Name
    }

    # Providers is a set of overrides to the default @config based on
    # well-known email service providers,
    # 2018-04: AOL and Yahoo now under "oath.com", owned by Verizon.
    @providers = {
      aol: {
        host_match: %w[aol. compuserve. netscape. aim. cs.]
      },
      google: {
        host_match: %w[gmail.com googlemail.com],
        exchanger_match: %w[google.com googlemail.com],
        local_size: 5..64,
        local_private_size: 1..64, # hostname not in host_match (private label)
        mailbox_canonical: ->(m) { m.gsub('.', '') }
      },
      msn: {
        host_match: %w[msn. hotmail. outlook. live.],
        mailbox_validator: ->(m, _) { m =~ /\A[a-z][\-\w]*(?:\.[\-\w]+)*\z/i }
      },
      yahoo: {
        host_match: %w[yahoo. ymail. rocketmail.],
        exchanger_match: %w[yahoodns yahoo-inc]
      }
    }

    # Loads messages: {"en"=>{"email_address"=>{"invalid_address"=>"...",}}}
    # Rails/I18n gem: t(email_address.error, scope: "email_address")
    @error_messages = YAML.load_file(File.dirname(__FILE__) + '/messages.yaml')

    ############################################################################
    # Class Methods [Configuration]
    ############################################################################

    # Call with a configuration hash of overrides to create a provider.
    def self.provider(name, config = {})
      name = name.to_sym
      unless config.empty?
        @providers[name] ||= @defaults.clone
        @providers[name].merge!(config)
      end
      @providers[name]
    end

    # Set multiple default configuration settings
    def self.configure(config = {})
      @defaults.merge!(config)
    end

    def self.setting(name, *value)
      @defaults[name.to_sym] = value.first unless value.empty?
      @defaults[name.to_sym]
    end

    ############################################################################
    # Instance Methods
    ############################################################################

    # Creates a new configuration instance, with optional per-call overrides.
    def initialize(config = {})
      @config = self.class.defaults.merge(config)
      @config[:providers] = self.class.providers
    end

    def providers(name)
      self.class.providers
    end

    # Merges provider settings into current settings.
    # Note: may override settings passed via new()
    def provider(name)
      config = self.class.providers[name.to_sym]
      @config.merge!(config) if config
    end

    # Returns a configuration setting
    def [](setting)
      @config[setting.to_sym]
    end

    # Sets a configuration setting in this instance/context
    def set(config_hash)
      @config = @config.merge(config_hash)
    end

    # Returns the hash of Provider rules
    def providers
      self.class.providers
    end
  end
end
