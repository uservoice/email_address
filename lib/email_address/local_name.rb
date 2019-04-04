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
  #             Quotes Unnecessary:  az09_ . - ! # $ % & ' * + = ? ^ ` { | }
  #             Quotes Required   :  space " ( ) , : ; < > @ [ \ ]
  #             Example: "@user name"@example.com
  #
  # * Simple    Contains any valid order of characters not needing to be quoted.
  #
  #             Characters:  az09_ . - ! # $ % & ' * + = ? ^ ` { | }
  #             Pattern: [ az09_.-!#$%&'*+=?^`{|} ]+
  #             Example: /^.+regexp*n$/@example.com
  #
  # * Relaxed   One or more words, each followed by an optional punctuation character
  #             with all the symbols allowed in "simple"
  #
  #             Pattern: ( word [ .-!#$%&'*+=? ]? )*
  #             Example: user-name!@example.com
  #
  # * Normal    Like loose, but with a restricted character set
  #
  #             Pattern: ( word [ .-'+/ ]* )+
  #             Example: user/name-@example.com
  #
  # * Conventional - Like normal, but must begin and end with a word.
  #             This is the pattern likely to match most conventional user addresses.
  #             For tagged parts, the mailbox (left) is this format, the tag (right)
  #             can be simple?
  #
  #             Pattern: word ( [ .-'+ ]* word )*
  #             Example: miles.o'brian+tag@example.com
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

  class LocalName < EmailAddress::Standard
    # Note Unicode/ASCII choice is handled in parsing. Just use Unicode here
    # Local General format: ( word special-character )+
    SIMPLE =      /^ [\p{L}\p{N}_\.\-\'\+\/\!\#\$\%\&\*\=\?\^\`\{\|\}]+ $/ix;
    RELAXED =     /^ ( [\p{L}\p{N}_]+ [\.\-\'\+\/\!\#\$\%\&\*\=\?]? )+ $/ix;
    NORMAL =      /^ ( [\p{L}\p{N}_]+ [\.\-\'\+\/]? )+ $/ix; # (\w+ [.-'+/)]+)+
    CONVENTIONAL= /^ [\p{L}\p{N}_]+ ( [\.\-\'\+] [\p{L}\p{N}_]+ )? $/ix; # \w+ ([.-'+] \w+)+

    def initialize(email_address_string, config={})
      super(email_address_string, config)
      self.local = new Local(self.local_name)
      self.domain = new Domain(self.domain_name) # Punycode?
    end

    def to_s
      # localcomment + local + @ + domaincommment + domain
    end

    # Returns a hash of email address parts and errors
    #def data
    #   anything I want to add?
    #end

    # Validation at this level is a forgving regular expression and DNS check
    def valid?
      valid_local? && valid_domain?
    end


    private

    def valid_local?
      return false unless super.valid?
      case @config[:level]
      when :free
        !! @local_name.match(LOCAL_REGEX_FREE)
      when :loose
        !! @local_name.match(LOCAL_REGEX_LOOSE)
      when :normal
        !! @local_name.match(LOCAL_REGEX_NORMAL)
      when :strict
        !! @local_name.match(LOCAL_REGEX_STRICT)
      when :standard
        true
      else
        raise new StadardError("Unexpected EmailAddress level: #{@config[:level]}")
      end
    end

    def valid_domain?
    end
  end
end
