# frozen_string_literal: true

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
  # * Base & Tags
  # * Reference (MD5)
  # * Canonical
  # * Digest
  # * Redacted
  # * Munged
  # * SRS/PRVS/BATV
  # * VERP/Qmail

  class Local
    # Note Unicode/ASCII choice is handled in parsing. Just use Unicode here
    # Local General format: ( word special-character )+
    SIMPLE =      /^ [\p{L}\p{N}_\.\-\'\+\/\!\#\$\%\&\*\=\?\^\`\{\|\}]+ $/ix
    RELAXED =     /^ ( [\p{L}\p{N}_]+ [\.\-\'\+\/\!\#\$\%\&\*\=\?]? )+ $/ix
    USER =        /^ [\p{L}\p{N}_]+ ( [\.\-\'\+] [\p{L}\p{N}_]+ )? $/ix # \w+ ([.-'+] \w+)+

    MD5_DIGEST =  /^ [0-9a-f]{32} $/ix
    SHA1_DIGEST = /^ [0-9a-f]{40} $/ix
    REDACTED =    /^ \{ [0-9a-f]{32,40} \} $/ix
    MUNGED =      /^ \w+\*+ $/ix
    SRS =         /\A SRS0= (....) = (\w\w) = (.+?) = (.+?) $/ix
    BATV =        /\A pvrs= (.) (\d\d\d) ([0-9a-f]{6}) = (.+) $/ix # pvrs=KDDDSSSSSS=user
    VERP =        /^ (.+) = ([\w\-\.]+) $/ix # local-remote=rdomain@ldomain

    LEVELS = %i( invalid standard simple relaxed user esp )

    # Only 'postmaster' is defined in RFC's
    ROLE_ACCOUNTS = %q( postmaster listmaster webmaster abuse info contact )

    attr_accessor :name
    attr_accessor :comment_left
    attr_accessor :comment_right
    attr_accessor :provider
    attr_reader :original
    attr_reader :mailbox
    attr_reader :tag
    attr_reader :errors

    def initialize(name=nul, config={})
      @config = config
      self.name = name if name
    end

    def name=(name)
      @errors = []
      @original = name
      @name = name
      @name.downcase! if @config[:local_downcase]
      #parse
      #edit
    end

    def provider=(provider_config)
      @config.merge(provider_config)
    end

    def self.valid?(name, config={})
      new(name,config).valid?
    end

    # Validation at this level is a forgving regular expression and DNS check
    def valid?
      valid_local? && valid_domain?
    end

    def to_s
      self.local_name
    end

    def data
      { name: @name,
        comment_left: @comment_left,
        comment_right: @comment_right,
        mailbox: @mailbox,
        tag: @tag,
        errors: @errors
      }
    end

    def inspect
      "<#EmailAddress::Local "+data.inspect+">"
    end

    private

    # RFC 5233 Calls this "Subaddress Extension" and name is USER and DETAIL
    def parse
      if @address.provider.tag_separator
        @mailbox, @tag = @name.split(@address.provider.tag_separator)
      else
        @mailbox = @name
        @tag = nil
      end
    end

    def level
      if !@address.valid?
        :invalid
      #elsif @address.matches_provider? # To be implemented
      #  :esp
      elsif @local_name.match(USER)
        :user
      elsif @local_name.match(RELAXED)
        :relaxed
      elsif @local_name.match(SIMPLE)
        :simple
      else
        :standard
      end
    end

    FORMATS = %i( invalid standard user md5 sha1 redacted munged srs batv verp )
    def format
      if !@address.valid?
        :invalid
      elsif @local_name.match(MD5_DIGEST)
        :md5
      elsif @local_name.match(SHA1_DIGEST)
        :sha1
      elsif @local_name.match(REDACTED)
        :redacted
      elsif @local_name.match(MUNGED)
        :munged
      elsif @local_name.match(SRS)
        :srs
      elsif @local_name.match(BATV)
        :batv
      elsif @local_name.match(VERP)
        :verp
      elsif @local_name.match(NORMAL)
        :user
      else
        :standard
      end
    end

    private
  end
end
