# frozen_string_literal: true

require 'simpleidn'
module EmailAddress
  # Defines the "Domain" part of the email address
  class Domain
    DOMAIN_NAME_REGEX =
      /^( [\p{L}\p{N}]+ (?: (?: \-{1,2} | \.) [\p{L}\p{N}]+ )* )(.*)/x.freeze
    FORMATS = %i[default localhost ipv4 ipv6 subdomain fqdn].freeze
    # Sometimes, you just need a Regexp...
    DNS_HOST_REGEX =
      / [\p{L}\p{N}]+ (?: (?: \-{1,2} | \.) [\p{L}\p{N}]+ )*/x.freeze

    # The IPv4 and IPv6 were lifted from Resolv::IPv?::Regex and tweaked to not
    # \A...\z anchor at the edges.
    IPV6_HOST_REGEX = /\[IPv6:
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
         )))\]/ix.freeze

    IPV4_HOST_REGEX = /\[((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?))\.((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?))\.((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?))\.((?x-mi:0
               |1(?:[0-9][0-9]?)?
               |2(?:[0-4][0-9]?|5[0-5]?|[6-9])?
               |[3-9][0-9]?))\]/x.freeze

    # Matches conventional host name and punycode: domain.tld, x--punycode.tld
    CANONICAL_HOST_REGEX = /\A #{DNS_HOST_REGEX} \z/x.freeze

    # Matches Host forms: DNS name, IPv4, or IPv6 formats
    STANDARD_HOST_REGEX = /\A (?: #{DNS_HOST_REGEX} | #{IPV4_HOST_REGEX}
                               | #{IPV6_HOST_REGEX}) \z/ix.freeze

    attr_reader :name
    attr_reader :original
    attr_reader :errors
    attr_accessor :format
    attr_accessor :comment_left
    attr_accessor :comment_right
    attr_accessor :subdomain, :apex_name, :sld, :tld, :ip
    attr_accessor :apex_domain, :fqdn, :punycode, :provider

    def initialize(name = nil, config = {})
      @errors = []
      @config = config
      @dns = config[:dns_lookup] == :off ? nil : DNSCache.instance
      self.name = name
    end

    def dns(name = @name)
      return nil if !@dns || !name

      @dns.lookup(name)
    end

    def name=(name)
      @errors = []
      @original = name
      @provider = @subdomain = @apex_name = @sld = @tld = @ip = nil
      @apex_domain = @fqdn = @punycode = nil
      parse(name) if name
    end

    # The exploded domain data
    def data
      { name: @name, format: @format,
        comment_left: @comment_left, comment_right: @comment_right,
        apex_name: @apex_name, apex_domain: @apex_domain, # example.com
        tld: @tld, sld: @sld, tlds: tlds,
        subdomain: @subdomain, fqdn: @fqdn, # "sub.domain.sld.tld."
        ip_address: @ip, # 127.0.0.1 or ::1
        idn: idn?, punycode: @punycode, # for IDN
        errors: @errors }
    end

    def inspect
      '<#EmailAddress::Domain ' + data.inspect + '>'
    end

    # The normalized DNS domain name, punycode if IDN
    def to_s
      @punycode || @name
    end

    # The full address domain, with comments
    def full
      [@comment_left, @name, @comment_right].compact.join
    end

    # A string of second and top level domain names
    def tlds
      [@sld, @tld].compact.join('.')
    end

    # true if this is a IDN/International Domain Name
    def idn?
      @punycode =~ /\A^xn--/ || @name =~ /\A^xn--/
    end

    def self.valid?(name, config = {})
      new(name, config).valid?
    end

    def valid?
      @errors.empty?
    end

    # Takes a email address string, returns true if it matches a rule
    # Rules of the follow formats are evaluated:
    # * "mail.ruby-lang.org" => Exact match to name/punycode/FQDN
    # * "example."  => apex name, any sld/tld
    # * ".com"      => root matches (ends with)
    # * "google"    => email service provider designation
    # * "@goog*.com" => Glob match
    # * "192.168.1.1/32" => IPv4/IPv6 CIDR Address of IP
    # * "192.168.1.1/32" => IPv4/IPv6 CIDR Address of MX hosts
    def matches?(rules)
      rules = Array(rules)
      return false if rules.empty?

      rules.each do |rule|
        [@name, @provider, @punycode, @fqdn, @ip].each do |v|
          if v && rule.is_a?(Regexp)
            return true if v =~ rule
          elsif v && rule == v
            return true
          end
        end
        next unless rule.is_a?(String)
        return true if rule.end_with?('.') && @apex_name == rule[0..-2]
        return true if rule.start_with?('.') && @name.end_with?(rule)

        [@name, @punycode, @fqdn, @ip].each do |v|
          return true if v && File.fnmatch?(rule, v)
        end
        return true if ip_matches?(ip, rule)
      end
      false
    end

    def parse(name)
      name = parse_comment(name)
      if (m = name.match(/\A\[IPv6:(.+)\]/i))
        self.ipv6 = m[1]
      elsif (m = name.match(/\A\[(\d{1,3}(\.\d{1,3}){3})\]/)) # IPv4
        self.ipv4 = m[1]
      else
        name = name.gsub(/\s+/, '') if @config[:host_remove_spaces]
        name = fully_qualified_domain_name(name.downcase)
        parse_dns_name(name)
        check_dns if dns
      end
      find_provider
    end

    private

    def ipv6=(ip)
      @ip = ip.downcase.gsub(/\b0+/, '') # Remove leading zeroes
      @name = "[IPv6:#{@ip}]"
      @format = :ipv6
      add_error(:no_ip_domain) unless @config[:host_allow_ip]
    end

    def ipv4=(ip)
      @ip = ip.gsub(/\b0+([1-9])/, '\1') # Remove leading zeroes
      @name = "[#{@ip}]"
      @format = :ipv4
      add_error(:no_ip_domain) unless @config[:host_allow_ip]
    end

    def parse_domain_ip(str)
      if str.start_with?('[') # (Comment)
        m = str.match(IPV4_HOST_REGEX)
        if m
          @domain_type = :ipv4
        else
          m = str.match(IPV6_HOST_REGEX)
          @domain_type = :ipv6 if m
        end
        if m
          if @domain_name == ''
            @domain_name += m[1]
          else
            add_error(:invalid_address, 'Unexpected IP Address')
          end
          str = m[2]
        else
          add_error(:invalid_address, 'Unexpected Left Bracket')
          str = str[1, str.size - 1]
        end
      end
      str
    end

    # def parse_domain_name(str)
    #   m = str.match(DOMAIN_NAME_REGEX)
    #   if m && @domain_name == ''
    #     @domain_name += m[1]
    #     if @domain_name.length > 253
    #       add_error(:invalid_address, 'Domain Name Too Long')
    #     else
    #       @domain_name.split('.').each do |label|
    #         if label.length > 63
    #           add_error(:invalid_address, 'Domain Level Name Too Long')
    #         end
    #       end
    #     end
    #   elsif m
    #     add_error(:invalid_address, 'Unexpected IP Address')
    #     str = m[2]
    #   else
    #     add_error(:invalid_address, 'Unexpected Character')
    #     str = str[1, str.size - 1]
    #   end
    #   str
    # end

    def parse_dns_name(name)
      if name =~ /[^[:ascii:]]/ # IDN
        set_idn(name)
      elsif name =~ /\A^xn--/ # Punycode
        set_punycode(name)
      elsif name == 'localhost'
        set_localhost
      else
        set_domain
      end

      @name = name
      if name =~ /[^[:ascii:]]/
        set_idn(name)
        add_error(:no_idn) unless @config[:allow_idn]
        @punycode = ::SimpleIDN.to_ascii(name)
      elsif name =~ /\A^xn--/
        @punycode = name
        @name = ::SimpleIDN.to_unicode(name)
      else
        @punycode = name
      end

      if name == 'localhost'
        @format = :localhost
        add_error(:no_localhost) unless @config[:allow_localhost]
      elsif name.index('.').nil?
        add_error(:incomplete_domain)
        # or assume xxx.com?
      elsif parse_fqdn(name)
      else
        add_error(:mailformed_domain)
      end
    end

    # Split sub.domain from .tld: *.com, *.xx.cc, *.cc
    def parse_fqdn(name)
      sub_apex = parse_tld(name)
      return false if sub_apex == name # parse failed

      if (m = sub_apex.match(/\A(.+)\.(.+)\z/)) # subdomainx.apex
        @subdomain = m[1]
        @apex_name = m[2]
      else
        @apex_name = sub_apex
      end
      @apex_domain = [@apex_name, @sld, @tld].compact.join('.')
    end

    # Parses TLD's off domain name. Returns name, unchanged if failed
    def parse_tld(name)
      if (m = name.match(/\A(.+)\.(\w{3,10})\z/)) || # (1=apex).(2=tld)
         (m = name.match(/\A(.+)\.(\w{1,3})\.(\w\w)\z/)) || # (apex).(sld).(tld)
         (m = name.match(/\A(.+)\.(\w\w)\z/)) # (1=apex).(2=tld/2char)
        name = m[1]
        @sld = m[2] if m[3]
        @tld = m[3] || m[2]
      end
      name
    end

    # Attempts to complete a FQDN
    def fully_qualified_domain_name(name)
      return name if name == 'localhost' || !@dns
      return name unless partial_fqdn(name)

      name = find_fqdn(name)
      return name if @fqdn

      add_error(:domain_not_found)
      name
    end

    # Looks up "name." in DNS, so is a FQDN, returns boolean
    def partial_fqdn(name)
      return false unless @config[:allow_partial_fqdn]

      @fqdn = name + '.' if dns(name + '.').valid?(:host)
      @fqdn ? true : false
    end

    def find_fqdn(name)
      DNSCache.instance.dns_config[:search].each do |base|
        if dns(name + '.' + base + '.').valid?(:host)
          @fqdn = name + '.' + base + '.'
          return name + '.' + base
        end
      end
      name
    end

    def parse_comment(name)
      if (m = name.match(/\A\((.+?)\)(.+)/)) # (comment)domain.tld
        @comment_left = m[1]
        name = m[2]
      end
      if (m = name.match(/\A(.+)\((.+?)\)\z/)) # domain.tld(comment)
        @comment_right = m[2]
        name = m[1]
      end
      name
    end

    def check_dns
      return true unless dns
      return true if @ip
      return true if dns(@fqdn || @name + '.').valid?(
        @config[:dns_lookup] || :mx
      )

      add_error(:host_unknown, 'Unknown Domain or missing MX', @name)
    end

    def find_provider
      # p '------------------------------> ' + @name
      # p dns.mx_hosts
      EmailAddress::Config.providers.each do |provider, config|
        if config[:host_match] && matches?(config[:host_match])
          return set_provider(provider, config)
        end
        # p [:unf, provider, config]
      end
      return set_provider(:default) unless dns

      EmailAddress::Config.providers.each do |provider, config|
        dns.mx_hosts.each do |mx| # {:host,:ipv4,:ipv6,:preference}
          next if mx[:host] == @name # Same host

          host = Domain.new(mx[:host])
          if host.matches?(config[:host_match])
            # p [:mxm, rule, mx]
            return set_provider(provider, config)
          end
        end
      end

      # provider = self.exchangers.provider
      # if provider && provider != :default
      #   p [253, provider]
      #   self.set_provider(provider,
      #     EmailAddress::Config.provider(provider))
      # end

      @provider || set_provider(:default)
    end

    def set_provider(name, provider_config = nil) # :nodoc:
      provider_config ||= EmailAddress::Config.providers[name]
      # p [:set_provider, @name, name, provider_config]
      @config = EmailAddress::Config.all_settings(provider_config, @config)
      @provider = name
    end

    def add_error(message, hint = nil, data = nil)
      # p [:add_error, message, hint, data]
      @errors << { message: message, hint: hint, data: data }
    end

    ############################################################################
    # Matching
    ############################################################################

    # def mx_matches?(rule)
    #   return false unless @dns
    #   @dns.mx_hosts.each do |mx| # {:host,:ipv4,:ipv6,:preference}
    #     host = Domain.new(mx[:host])
    #     p [:mxm, rule, mx]
    #     return true if host.matches?(rule)
    #     ips = rule.include?(':') ?  mx[:ipv6] : mx[:ipv4]
    #     ips.each do |ip|
    #       return true if DNS.in_cidr?(ip, rule)
    #     end
    #   end
    #   false
    # end

    # True if the host is an IP Address form, and that address matches
    # the passed CIDR string ('10.9.8.0/24' or '2001:..../64')
    def ip_matches?(ip, cidr)
      DNS.in_cidr?(ip, cidr)
    end
  end
end
