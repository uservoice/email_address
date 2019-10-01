# frozen_string_literal: true

module EmailAddress
  # Represents an RFC-2822 Email Address with parser/validator
  # Acts as a base class for other email address types
  # Use as Email Address standard syntax checker and parser.
  class Address
    attr_reader :address # string "local@domain"
    attr_reader :original
    attr_reader :errors
    attr_reader :local
    attr_reader :domain

    def initialize(address, config = {})
      @config = EmailAddress::Config.new(config)
      @errors = []
      @local = EmailAddress::Local.new(nil, config)
      @domain = EmailAddress::Domain.new(nil, config)
      self.address = address
    end

    def address=(address_string)
      @errors = []
      @original = address_string
      @address = address_string
      parse(address_string)
      @errors += @local.errors
      @errors += @domain.errors
      # #@errors += provider.errors
    end

    # Returns a hash of email address parts and errors
    def data
      { address: address,
        domain: @domain.data,
        local: @local.data,
        provider: nil, # self.domain.provider_name,
        valid: valid?,
        errors: @errors }
    end

    def inspect
      '<#EmailAddress::Address ' + data.inspect + '>'
    end

    def to_s
      [local.name, domain.name].join('@')
    end

    def self.valid?(name, config = {})
      new(name, config).valid?
    end

    # Validation at this level is purely syntactic. No DNS validation.
    def valid?
      @errors.empty?
    end

    # Tokenizer Regexen to parse off the next token.
    # Token in match_data[1] and the rest of the string in match_data[2]
    UNICODE_TOKEN_ATOM  =
      %r/^([\p{L}\p{N}\-\!\#\$\%\&\'\*\+\/\=\?\^\`\{\|\}\~]+)(.*)/i.freeze
    UNICODE_QUOTED_ATOM =
      /^(\"(?:\\[\"\\]|
        [\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7E\p{L}\p{N}])+\")
        (.*)/ix.freeze
    ASCII_TOKEN_ATOM    = #  AZaz09_!#$%&'*+-/=?^`{|}~
      %r/^([\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+)(.*)/i.freeze
    ASCII_QUOTED_ATOM   = # Addl space "(),:;<>@[\] escaped \\ and \"
      /^(\"(?:\\[\"\\]|
        [\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7EA-Za-z0-9])+\")
        (.*)/ix.freeze
    COMMENT_TEXT        = /^(\(.*?\))(.*)/i.freeze

    private

    # Parses the incoming email address string into these components:
    #   @local.name - Essentially, the left-hand side of the @
    #   @local.comment_left, @local_comment_right - local part comments
    #   @domain.name - Essentially, the right-hand side of the @
    #   @domain.type - :dns, :ipv4, :ipv6, :localhost?, :non_fqdn
    #   @domain.comment_left, @domain_comment_right - domain part comments
    #   @errors - Any parsing errors encountered
    def parse(address)
      @local_name = @local_comment_left = @local_comment_right = ''
      configure_atom_defs
      @address = correct_address(address)
      domain_string = @local.parse(address)
      @domain.parse(domain_string)
      [@local_name, @domain_name]
    end

    def configure_atom_defs
      if @config[:unicode]
        @token_atom = UNICODE_TOKEN_ATOM
        @quoted_atom = UNICODE_QUOTED_ATOM
      else
        @token_atom = ASCII_TOKEN_ATOM
        @quoted_atom = ASCII_QUOTED_ATOM
      end
    end

    def parse_atom(str)
      m = str.match(@token_atom)
      if m
        @local_name += m[1]
        str = m[2]
      else
        add_error(:invalid_address, 'Unexpected character', str)
        str = str[1, str.size - 1]
      end
      str
    end

    def parse_quoted_token(str)
      return nil unless str.start_with?('"')

      m = str.match(@quoted_atom)
      if m
        @local_name += m[1]
        str = m[2]
      else
        add_error(:invalid_address, 'Unexpected quote', str)
        str = str[1, str.size - 1]
      end
      str
    end

    # Returns new [str, value, left, right]
    # This is called by local and domain parsing
    def parse_comment(str, value = '', left = '', right = '')
      m = str.match(COMMENT_TEXT)
      if m
        if value == ''
          add_error(:invalid_address, 'Unexpected Comment', str) if left != ''
          left += m[1] || ''
        else
          add_error(:invalid_address, 'Unexpected Comment', str) if right != ''
          right += m[1]
        end
        str = m[2]
      else
        add_error(:invalid_address, 'Unexpected Left Parenthesis', str)
        str = str[1, str.size - 1]
      end
      [str, value, left, right]
    end

    def add_error(message, hint = nil, data = nil)
      # #p [:add_error, message, hint, data]
      @errors << { message: message, hint: hint, data: data }
    end

    def transform_case(str, style)
      case style
      when :lower
        str.downcase
      when :upper
        str.upcase
      else
        str
      end
    end
  end
end
