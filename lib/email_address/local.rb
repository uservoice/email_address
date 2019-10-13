# frozen_string_literal: true
require 'digest'

module EmailAddress

  # Represents a Email Address Local Name. It comes from parsing the
  # email address string into a EmailAddress::Standard and is controlled
  # through the rules for the Email Service Provider (ESP) or domain name.
  # Validity here requires validity from the parsing step.
  #
  # Strictness Level of the local_name (without comments):
  # ! az09_ or (\w) Word-Characters are Letters, Numbers, and if configured,
  # ! Unicode Letters/Words and Numbers, as well as underscore.
  #
  # * Standard  Email Address local parts contain characters that would
  #             would quoting or escaping, properly done so.
  #
  #             Quotes Unnecessary:  AZaz09_ . - ! # $ % & ' * + = ? ^ ` { | }
  #             Quotes Required   :  space " ( ) , : ; < > @ [ \ ]
  #             Example: "@user name"@example.com
  #
  # * Illegal   Valid user, but doesn't meet known ESP rules.
  #
  # * Simple    Contains any valid order of characters not needing to be quoted.
  #
  #             Characters:  AZaz09_ . - ! # $ % & ' * + = ? ^ ` { | }
  #             Pattern: [ AZaz09_.-!#$%&'*+=?^`{|} ]+
  #             Example: /^.+regexp*n$/@example.com
  #
  # * Relaxed   One or more words, each followed by an optional punctuation character
  #             with all the symbols allowed in "simple"
  #             Uppercase characters should be converted to lowercase.
  #             This version should work with special automated email addresses
  #             like return paths, VERP, SRS and BATV encoded addresses.
  #
  #             Pattern: ( word [ .-!#$%&'*+=? ]? )*
  #             Example: user-name!@example.com
  #
  # * User      Like relaxed, but must begin and end with a word. Less allowed puctuation
  #             This is the pattern likely to match most conventional user addresses.
  #             For tagged parts, the mailbox (left) is this format, the tag (right)
  #             can be simple?
  #
  #             Pattern: word ( [ .-'+ ]* word )*
  #             Example: miles.o'brian+tag@example.com
  #
  # * ESP       Valid according to any pref-defined Email Service Provider formats:
  #             Google (gmail), Microsoft (hotmail/live/msn/outlook), Yahoo, AOL, Apple, etc.
  #-----------------------------------------------------------------------------
  # Other forms of the email address local name:
  #
  # * :original - The format passed to `EmailAddress`.
  # * :normal - Normalized address is lower case (if configured) and cleaned up.
  # * :mailbox - Normalized address with any tags (subaddresses) removed.
  # * :canonical - Address is re-written as a base user/mailbox address. Non-identifiable character such as gmail-dots and "tags" are removed.
  # * :reference - MD5 (and sometimes SHA1) digests of email addresses are used to query the address while maintaining privacy.
  # * :redacted - Addresses that have been removed from your database (such as GDPR) but maintain a placeholder for accounting.
  # * :munged - An obsfucated address to be transmitted on public web pages, email messages, etc.
  # * :srs - Sender Rewriting Scheme (SRS) allows an address to be forwarded from the original owner and encoded to be used with the domain name of the sender.
  # * :batv - Bounce Address Tag Validation.
  # * :prvs - Simple Private Signature.
  # * :verp - Variable Envelope Return Path, this embeds the recipient address within a special return path address.

  class Local
    # Note Unicode/ASCII choice is handled in parsing. Just use Unicode here
    # Local General format: ( word special-character )+
    SIMPLE =      /^ [\p{L}\p{N}_\.\-\'\+\/\!\#\$\%\&\*\=\?\^\`\{\|\}]+ $/ix
    RELAXED =     /^ ( [\p{L}\p{N}_]+ [\.\-\'\+\/\!\#\$\%\&\*\=\?]? )+ $/ix
    USER =        /^ [\p{L}\p{N}_]+ ( [\.\-\'\+] [\p{L}\p{N}_]+ )* $/ix # \w+ ([.-'+] \w+)+

    MD5_DIGEST =  /^ [0-9a-f]{32} $/ix
    SHA1_DIGEST = /^ [0-9a-f]{40} $/ix
    REDACTED =    /^ \{ [0-9a-f]{32,40} \} $/ix # {md5|sha1}@domain
    MUNGED =      /^ \w+\*+ $/ix                # x****@domain -- invalid
    SRS =         /\A SRS0= (....) = (\w\w) = (.+?) = (.+?) $/ix
    BATV =        /\A pvrs= (.) (\d\d\d) ([0-9a-f]{6}) = (.+) $/ix # pvrs=KDDDSSSSSS=user
    VERP =        /^ (.+) = ([\w\-\.]+) $/ix # local-remote=rdomain@ldomain

    # Tokenizer Regexen to parse off the next token. Token in match_data[1] and the rest of the string in match_data[2]
    UNICODE_TOKEN_ATOM  = /^([\p{L}\p{N}_\-\!\#\$\%\&\'\*\+\/\=\?\^\`\{\|\}\~]+)(.*)/i;
    UNICODE_QUOTED_ATOM = /^(\"(?:\\[\"\\]|[\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7E\p{L}\p{N}])+\")(.*)/i;
    ASCII_TOKEN_ATOM    = /^([\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+)(.*)/i; #  AZaz09_!#$%&'*+-/=?^`{|}~
    ASCII_QUOTED_ATOM   = /^(\"(?:\\[\"\\]|[\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7EA-Za-z0-9])+\")(.*)/i; # Addl space "(),:;<>@[\] escaped \\ and \"
    COMMENT_TEXT        = /^(\(.*?\))(.*)/i;

    # Only 'postmaster' is defined in RFC's
    ROLE_ACCOUNTS = %q( postmaster listmaster webmaster abuse info contact )
    LEVELS        = {invalid:0, illegal:1, standard:2, simple:3, relaxed:4, user:5, esp:6}
    FORMATS       = %i( invalid standard user md5 sha1 redacted munged srs batv verp )

    attr_reader :comment_left
    attr_reader :comment_right
    attr_reader :name
    attr_accessor :provider
    attr_reader :original
    attr_reader :mailbox
    attr_reader :tag
    attr_reader :separator
    attr_reader :errors

    def initialize(name = nil, config = {})
      @config = config.is_a?(Config) ? config : Config.new(config)
      parse(name) if name
    end

    def name=(name)
      parse(name)
    end

    # Parses string into local part, up to "@" domain part, returns remaining part.
    def parse(string)
      @errors = []
      @name = @comment_left = @comment_right = @tag = ''
      remaining = parse_local(string)
      @name.downcase! if @config[:local_downcase]
      parse_address_tag
      @level = LEVELS[ @errors.count==0 ? :invalid : :standard ]
      @original = string[0, string.size - remaining.size - 1]
      if @config[:local_encoding] == :ascii && @name =~ /([^[:ascii:]]+)/
        add_error(:invalid_address, "Unicode not accepted", $1)
      end
      @name = @name.unicode_normalize(:nfkc) # Helps for uniqueness
      remaining
    end

    def unicode?
      @name =~ /[^[:ascii:]]/
    end

    def provider=(provider_config)
      @config.merge(provider_config)
    end

    def self.valid?(name, config={})
      new(name,config).valid?
    end

    # Validation at this level is a forgving regular expression and DNS check
    def valid?
      @errors.count == 0
    end

    # Returns the normalized version of the name+tag, no comments
    def to_s
      @name
    end

    def data
      { name: @name,
        comment_left: @comment_left,
        comment_right: @comment_right,
        mailbox: @mailbox,
        tag: @tag,
        separator: @separator,
        errors: @errors
      }
    end

    def inspect
      "<#EmailAddress::Local "+data.inspect+">"
    end

    def level
      if @errors.count > 1
        :invalid
      #elsif @address.matches_provider? # To be implemented
      #  :esp
      elsif @name.match(USER)
        :user
      elsif @name.match(RELAXED)
        :relaxed
      elsif @name.match(SIMPLE)
        :simple
      else
        :standard
      end
    end

    def level_at_least?(min_level = :standard)
      LEVELS[level] >= LEVELS[min_level]
    end

    def format
      if !@address.valid?
        :invalid
      elsif @name.match(MD5_DIGEST)
        :md5
      elsif @name.match(SHA1_DIGEST)
        :sha1
      elsif @name.match(REDACTED)
        :redacted
      elsif @name.match(MUNGED)
        :munged
      elsif @name.match(SRS)
        :srs
      elsif @name.match(BATV)
        :batv
      elsif @name.match(VERP)
        :verp
      elsif @name.match(NORMAL)
        :user
      else
        :standard
      end
    end

    # Forms ####################################################################

    # Returns the full local, including comments, and normalized name
    def full
      f = []
      f << '('+@comment_left+')' if @comment_left > ' '
      f << @name
      f << @separator + @tag if @tag > ' '
      f << @name
      f << '('+@comment_right+')' if @comment_right > ' '
      f.join()
    end

    # Returns a canonical form of the address
    def canonical
      if @config[:mailbox_canonical]
        @config[:mailbox_canonical].call(@mailbox)
      else
        @mailbox.downcase
      end
    end

    def canonical?
      @name == canonical
    end

    def canonical!
      @tag = @comment_left = @comment_right = ''
      @name = @mailbox = canonical
    end

    def reference(method=nil)
      if method.nil? || method == :md5
        Digest::MD5.hexdigest(@name) ### ????? Canonical?
      else
        Digest::SHA1.hexdigest(@name)
      end
    end

    def munge
      @mailbox.sub(/\A(.{1,2}).*/) { |m| $1 + @config[:munge_string] }
    end

    def redact
      Digest::MD5.hexdigest(@name) ### ????? Canonical?
    end

    def redact!
      @tag = @comment_left = @comment_right = ''
      @name = @mailbox = Digest::MD5.hexdigest(@name) ### ????? Canonical?
    end

    private ####################################################################

    # RFC 5233 Calls this "Subaddress Extension" and name is USER and DETAIL
    def parse_address_tag(separator="+")
      return unless level_at_least?(:relaxed)
      if separator
        @separator = separator
        @mailbox, @tag = @name.split(separator)
      else
        @mailbox = @name
        @tag = nil
      end
    end

    def parse_local(str)
      @comment_left = @comment_right = ''
      @token_atom, @quoted_atom = UNICODE_TOKEN_ATOM, UNICODE_QUOTED_ATOM
      while str.length > 0
        #p [:parse_local,str,@name, @errors]
        case str[0]
        when '"'
          if @name == ''
            str = parse_quoted_token(str)
          else
            add_error(:invalid_address, "Unexpected Quote", str)
            str = str[1..]
          end
        when '('
          updates = parse_comment(str, @name, @comment_left, @comment_right)
          str, @name, @comment_left, @comment_right = *updates
          @comment_left = @comment_left
          @comment_right = @comment_right
        when '@'
          str = str[1..]
          break
        when '.'
          @name += '.'
          if str[1,1] == '.'
            add_error(:invalid_address, "No consecutive dots") # "No empty atoms"
            str = str[2..]
          elsif str[1,1] == '"'
            str = parse_quoted_token(str[1..])
          else
            str = parse_atom(str[1..])
          end
        else # atom
          str = parse_atom(str)
        end
      end
      if @name.length == 0
        add_error(:invalid_address, "Missing Local")
      elsif @name.length > 64
        add_error(:invalid_address, "Local Part Too Long")
      end

      #p [:parse_local,str,@name, @errors]
      str #=> remaining/unparsed string
    end

    def parse_atom(str)
      m = str.match(@token_atom)
      if m
        @name += m[1]
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
        @name += m[1]
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

    def add_error(message, hint=nil, data=nil)
      #p [:add_error, message, hint, data];
      @valid = false
      @errors << {message: message, hint: hint, data:data}
    end

  end
end
