# frozen_string_literal: true

module EmailAddress
  # Sometimes, you just need a Regexp...
  module Regex
    DOMAIN_NAME_REGEX =
      /^( [\p{L}\p{N}]+ (?: (?: \-{1,2} | \.) [\p{L}\p{N}]+ )* )(.*)/x.freeze

    DNS_HOST_REGEX =
      / [\p{L}\p{N}]+ (?: (?: \-{1,2} | \.) [\p{L}\p{N}]+ )*/x.freeze

    # The IPv4 and IPv6 were lifted from Resolv::IPv?::Regex and tweaked to not
    # \A...\z anchor at the edges.
    # [IPv6:2001:470:8:120e:1035:ea47:5d6d:b4c6]
    IPV6_FORMAT = /^\[IPv6:(.+)\]$/.freeze
    IPV6_HOST_REGEX = /\[IPv6:(
      (?: (?:(?x-mi:
      (?:[0-9A-Fa-f]{1,4}:){7}
         [0-9A-Fa-f]{1,4}
      )) |
      (?:(?x-mi:
      (?: (?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
      (?: (?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
      )) |
      (?:(?x-mi:
      (?: (?:[0-9A-Fa-f]{1,4}:){6,6})
      (?: \d+)\.(?: \d+)\.(?: \d+)\.(?: \d+)
      )) |
      (?:(?x-mi:
      (?: (?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::
      (?: (?:[0-9A-Fa-f]{1,4}:)*)
      (?: \d+)\.(?: \d+)\.(?: \d+)\.(?: \d+)
         ))))\]/ix.freeze

    # [127.0.0.1]
    IPV4_FORMAT = /^\[(.+)\]$/.freeze
    IPV4_HOST_REGEX = /\[((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?)\.((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?))\.((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?))\.((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?)))\]/x.freeze

    # Matches conventional host name and punycode: domain.tld, x--punycode.tld
    CANONICAL_HOST_REGEX = /\A #{DNS_HOST_REGEX} \z/x.freeze

    # Matches Host forms: DNS name, IPv4, or IPv6 formats
    STANDARD_HOST_REGEX = /\A (?: #{DNS_HOST_REGEX} | #{IPV4_HOST_REGEX}
                               | #{IPV6_HOST_REGEX}) \z/ix.freeze

    # Note Unicode/ASCII choice is handled in parsing. Just use Unicode here
    # Local General format: ( word special-character )+
    SIMPLE =
      %r/^ [\p{L}\p{N}_\.\-\'\+\/\!\#\$\%\&\*\=\?\^\`\{\|\}]+ $/ix.freeze
    RELAXED =
      %r/^ ( [\p{L}\p{N}_]+ [\.\-\'\+\/\!\#\$\%\&\*\=\?]? )+ $/ix.freeze
    USER = # \w+ ([.-'+] \w+)+
      /^ [\p{L}\p{N}_]+ ( [\.\-\'\+] [\p{L}\p{N}_]+ )* $/ix.freeze

    MD5_DIGEST =  /^ [0-9a-f]{32} $/ix.freeze
    SHA1_DIGEST = /^ [0-9a-f]{40} $/ix.freeze
    REDACTED =    /^ \{ [0-9a-f]{32,40} \} $/ix.freeze # {md5|sha1}@domain
    MUNGED =      /^ \w+\*+ $/ix.freeze                # x****@domain -- invalid
    SRS =         /\A SRS0= (....) = (\w\w) = (.+?) = (.+?) $/ix.freeze

    # pvrs=KDDDSSSSSS=user
    BATV =        /\A pvrs= (.) (\d\d\d) ([0-9a-f]{6}) = (.+) $/ix.freeze

    # local-remote=rdomain@ldomain
    VERP =        /^ (.+) = ([\w\-\.]+) $/ix.freeze

    # Tokenizer Regexen to parse off the next token. Token in match_data[1]
    # and the rest of the string in match_data[2]
    UNICODE_TOKEN_ATOM  =
      %r/^([\p{L}\p{N}_\-\!\#\$\%\&\'\*\+\/\=\?\^\`\{\|\}\~]+)(.*)/i.freeze

    UNICODE_QUOTED_ATOM =
      /^(\"(?:\\[\"\\]
            |[\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7E\p{L}\p{N}]
           )+\")(.*)/ix.freeze

    #  AZaz09_!#$%&'*+-/=?^`{|}~
    ASCII_TOKEN_ATOM    =
      %r/^([\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+)(.*)/i.freeze

    # Addl space "(),:;<>@[\] escaped \\ and \"
    ASCII_QUOTED_ATOM   =
      /^(\"(?:\\[\"\\]
            |[\x20-\x21\x23-\x2F\x3A-\x40\x5B\x5D-\x60\x7B-\x7EA-Za-z0-9]
           )+\")(.*)/ix.freeze
    COMMENT_TEXT        =
      /^(\(.*?\))(.*)/i.freeze

    # (1=comment) 2=data (3=comment)
    COMMENT_PARTS = /^ (?: \( (.*?) \) )? (.*?) (?: \( (.*) \) )? $/ix.freeze
  end
end
