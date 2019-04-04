# frozen_string_literal: true

module EmailAddress

  # Represents an RFC-2822 Email Address with parser/validator
  # Acts as a base class for other email address types
  # Use as Email Address standard syntax checker and parser.

  class Standard
    attr_reader :email_address_string
    attr_reader :local_name
    attr_reader :local_comment_left
    attr_reader :local_comment_right
    attr_reader :domain_name
    attr_reader :domain_type
    attr_reader :domain_comment_left
    attr_reader :domain_comment_right
    attr_reader :errors

    def initialize(email_address_string, config={})
      @email_address_string = email_address_string
      @config = config
      @errors = []
      parse(email_address_string)
    end

    # Returns a hash of email address parts and errors
    def data
      { email_address_string: self.email_address_string,
        local_name: self.local_name,
        local_comment_left: self.local_comment_left,
        local_comment_right: self.local_comment_right,
        domain_name: domain_name,
        domain_type: domain_type,
        domain_comment_left: domain_comment_left,
        domain_comment_right: domain_comment_right,
        valid: self.valid?,
        errors: self.errors,
      }
    end

    # Validation at this level is purely syntactic. No DNS validation.
    def valid?
      @errors.length == 0
    end

    # Tokenizer Regexen to parse off the next token. Token in match_data[1] and the rest of the string in match_data[2]
    UNICODE_TOKEN_ATOM  = /^([\p{L}\p{N}\-\!\#\$\%\&\'\*\+\/\=\?\^\`\{\|\}\~]+)(.*)/i;
    UNICODE_QUOTED_ATOM = /^(\"(?:\\[\"\\]|[\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7E\p{L}\p{N}])+\")(.*)/i;
    ASCII_TOKEN_ATOM    = /^([\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+)(.*)/i; #  AZaz09_!#$%&'*+-/=?^`{|}~
    ASCII_QUOTED_ATOM   = /^(\"(?:\\[\"\\]|[\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7EA-Za-z0-9])+\")(.*)/i; # Addl space "(),:;<>@[\] escaped \\ and \"
    COMMENT_TEXT        = /^(\(.*?\))(.*)/i;
    DOMAIN_NAME_REGEX   = /^( [\p{L}\p{N}]+ (?: (?: \-{1,2} | \.) [\p{L}\p{N}]+ )* )(.*)/x

    private

    # Parses the incoming email address string into these components:
    #   @local_name - Essentially, the left-hand side of the @
    #   @local_comment_left, @local_comment_right - Comments removed from the local part
    #   @domain_name - Essentially, the right-hand side of the @
    #   @domain_type - :dns, :ipv4, :ipv6, :localhost?, :non_fqdn
    #   @domain_comment_left, @domain_comment_right - Comments removed from the domain part
    #   @errors - Any parsing errors encountered
    def parse(email_address_string)
      @email_address_string = fold_white_space(email_address_string)
      if @config[:unicode]
        @token_atom, @quoted_atom = UNICODE_TOKEN_ATOM, UNICODE_QUOTED_ATOM
      else
        @token_atom, @quoted_atom = ASCII_TOKEN_ATOM, ASCII_QUOTED_ATOM
      end
      @local_name = @local_comment_left = @local_comment_right = ''
      @valid = true
      domain_string = parse_local(email_address_string)
      remaining = parse_domain(domain_string)
      if !@config[:parse_within] && remaining > ''
        add_error(:invalid_address, "Unexpected Extra text", remaining)
      end
      [@local_name, @domain_name]
    end

    def parse_local(str)
      while str.length > 0
        case str[0]
        when '"'
          if @local_name == ''
            str = parse_quoted_token(str)
          else
            add_error(:invalid_address, "Unexpected Quote", str)
            str = str[1..]
          end
        when '('
          updates = parse_comment(str, @local_name, @local_comment_left, @local_comment_right)
          str, @local_name, @local_comment_left, @local_comment_right = *updates
        when '@'
          str = str[1..]
          break
        when '.'
          @local_name += '.'
          if str[1,1] == '"'
            str = parse_quoted_token(str[1..])
          else
            str = parse_atom(str[1..])
          end
        else # atom
          str = parse_atom(str)
        end
      end
      @local_name = transform_case(@local_name, @config[:case])
      if @local_name.length == 0
        add_error(:invalid_address, "Missing Local")
      elsif @local_name.length > 64
        add_error(:invalid_address, "Local Part Too Long")
      end
      str
    end

    def parse_atom(str)
      m = str.match(@token_atom)
      if m
        @local_name += m[1]
        str = m[2]
      else
        add_error(:invalid_address, "Unexpected character", str)
        str = str[1..]
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
        add_error(:invalid_address, "Unexpected quote", str)
        str = str[1..]
      end
      str
    end

    # Returns new [str, value, left, right]
    # This is called by local and domain parsing
    def parse_comment(str, value='', left='', right='')
      m = str.match(COMMENT_TEXT)
      if m
        if value == ''
          if left != ''
            add_error(:invalid_address, "Unexpected Comment", str)
          end
          left += m[1] || ''
        else
          if right != ''
            add_error(:invalid_address, "Unexpected Comment", str)
          end
          right += m[1]
        end
        str = m[2]
      else
        add_error(:invalid_address, "Unexpected Left Parenthesis", str)
        str = str[1..]
      end
      [str, value, left, right]
    end

    def parse_domain(domain_string)
      @domain_name = @domain_comment_left = @domain_comment_right = ''
      str = domain_string
      while str.length > 0
        case str[0]
        when '('
          updates = parse_comment(str, @domain_name, @domain_comment_left, @domain_comment_right)
          if updates
            str, @domain_name, @domain_comment_left, @domain_comment_right = *updates
          end
        when '['
          str = parse_domain_ip(str)

        else # (label.)* label  name: [1..63]  total: [1..253]
          str = parse_domain_name(str)
          @domain_type = :dns # :localhost :non_fqdn
        end
      end
      if @domain_name.length == 0
        add_error(:invalid_address, "Missing Domain")
      end
      str
    end

    def parse_domain_ip(str)
      if str.start_with?('[') # (Comment)
        m = str.match(Host::IPv4_HOST_REGEX)
        if m
          @domain_type = :ipv4
        else
          m = str.match(Host::IPv6_HOST_REGEX)
          @domain_type = :ipv6 if m
        end
        if m
          if @domain_name == ''
            @domain_name += m[1]
          else
            add_error(:invalid_address, "Unexpected IP Address")
          end
          str = m[2]
        else
          add_error(:invalid_address, "Unexpected Left Bracket")
          str = str[1..]
        end
      end
      str
    end

    def parse_domain_name(str)
      m = str.match(DOMAIN_NAME_REGEX)
      if m
        if @domain_name == ''
          @domain_name += m[1]
          if @domain_name.length > 253
            add_error(:invalid_address, "Domain Name Too Long")
          else
            @domain_name.split(".").each do |label|
              if label.length > 63
                add_error(:invalid_address, "Domain Level Name Too Long")
              end
            end
          end
        else
          add_error(:invalid_address, "Unexpected IP Address")
        end
        str = m[2]
      else
        add_error(:invalid_address, "Unexpected Character")
        str = str[1..]
      end
      str
    end

    def add_error(message, hint=nil, data=nil)
      #p [:add_error, message, hint, data];
      @valid = false
      @errors << {message: message, hint: hint, data:data}
    end

    def fold_white_space(str)
      str.gsub(/\s+/, ' ')
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
