# frozen_string_literal: true

require 'simpleidn'
module EmailAddress
  # Parses and validates the "Domain" part of the email address
  # * Fully Qualified or Partial Domain Name
  # * IPv6 and IPv6 Address
  # * International Domain Name (IDN)
  # * DNS/Punycode Name (IDN escaped to ASCII DNS Name)
  class Domain
    FORMATS = %i[default localhost ipv4 ipv6 subdomain fqdn].freeze
    attr_reader :name, :dns_name, :original
    attr_reader :errors
    attr_reader :format
    attr_reader :comment_left, :comment_right
    attr_reader :subdomain, :apex_name, :sld, :tld, :ip, :tlds
    attr_reader :apex_domain, :fqdn, :punycode, :provider

    def initialize(name = nil, config = {})
      @errors = []
      @config = config.is_a?(Config) ? config : Config.new(config)
      @dns = @config[:dns_lookup] == :off ? nil : DNSCache.instance
      self.name = name if name
    end

    def name=(name)
      @errors = []
      @original = name
      @provider = @subdomain = @apex_name = @sld = @tld = @ip = nil
      @apex_domain = @fqdn = @dns_name = nil
      name = name.gsub(/\s+/, '') if @config[:host_remove_spaces]
      parse(name) if name
      find_provider
    end

    # The exploded domain data
    def data
      { name: @name, format: @format,
        comment_left: @comment_left, comment_right: @comment_right,
        apex_name: @apex_name, apex_domain: @apex_domain, # example.com
        tld: @tld, sld: @sld, tlds: @tlds,
        subdomain: @subdomain, fqdn: @fqdn, # "sub.domain.sld.tld."
        ip_address: @ip, # 127.0.0.1 or ::1
        idn: idn?, dns_name: @dns_name, # for IDN
        errors: @errors }
    end

    def inspect
      '<#EmailAddress::Domain ' + data.inspect + '>'
    end

    # The normalized DNS domain name, punycode if IDN
    def to_s
      @dns_name || @name
    end

    # The full address domain, with comments
    def full
      [@comment_left, @name, @comment_right].compact.join
    end

    # true if this is a IDN/International Domain Name
    def idn?
      @dns_name =~ /\A^xn--/ || @name =~ /\A^xn--/
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
        return true if test_match_rule(rule)
        next unless rule.is_a?(String)
        return true if rule.end_with?('.') && @apex_name == rule[0..-2]
        return true if rule.start_with?('.') && @name.end_with?(rule)
        return true if test_match_rule(rule, true)
        return true if ip_matches?(ip, rule)
      end
      false
    end

    def test_match_rule(rule, glob = false)
      [@name, @provider, @dns_name, @fqdn, @ip].each do |v|
        next unless v
        return true if rule.is_a?(Regexp) && v =~ rule
        return true if glob ? File.fnmatch?(rule, v.to_s) : v == rule
      end
      false
    end

    # Performs a DNS lookup of the given domain name
    def dns(name = @name)
      return nil if !@dns || !name

      @dns.lookup(name)
    end

    private ####################################################################

    def parse(name)
      name = parse_comment(name)
      if (m = name.match(Regex::IPV6_HOST_REGEX))
        self.ipv6 = m[1]
      elsif (m = name.match(Regex::IPV4_HOST_REGEX))
        self.ipv4 = m[1]
      elsif name == 'localhost'
        handle_localhost(name)
      else
        handle_domain_name(name)
      end
    end

    def ipv6=(ip)
      @ip = ip.downcase.gsub(/\b0+/, '') # Remove leading zeroes
      @name = "[IPv6:#{@ip}]"
      @format = :ipv6
      # Validip?
      add_error(:no_ip_domain) unless @config[:host_allow_ip]
    end

    def ipv4=(ip)
      @ip = ip.gsub(/\b0+([1-9])/, '\1') # Remove leading zeroes
      @name = "[#{@ip}]"
      @format = :ipv4
      # Validip?
      add_error(:no_ip_domain) unless @config[:host_allow_ip]
    end

    def handle_localhost(name)
      @format = :localhost
      @name = name
    end

    def handle_domain_name(name)
      @format = :fqdn
      if name =~ /[^[:ascii:]]/ # IDN
        self.idn = name
      elsif name =~ /\A^xn--/ # Punycode
        self.dns_name = name
      else
        name = name.gsub(/\s+/, '') if @config[:host_remove_spaces]
        self.fqdn = name
        check_dns
      end
    end

    def idn=(name)
      @idn = @name = name
      self.fqdn = name
      @dns_name = SimpleIDN.to_ascii(name)
    end

    def dns_name=(name)
      @dns_name = name.downcase
      self.fqdn = @dns_name
      @name = SimpleIDN.to_unicode(@dns_name)
    end

    # Attempts to complete a FQDN
    # A Fully-Qualified Domain Name (subdomain.apex_name.tld) is defined as a
    # FQDN when DNS lookup of "subdomain.apex_name.tld." (note the tailing dot)
    # resolves. Otherwise, it could be a subdomain on one of the "search
    # domains" defined in your resolver configuration (/etc/resolv.conf).
    # If the given name is not FQDN, it will try each search domain until the
    # name resolves, returning the FQDN on success or the name.
    def fqdn=(name)
      @fqdn = @name = name.downcase
      if @dns && @config[:allow_partial_fqdn] && !fqdn?(name)
        @fqdn = find_fqdn(name)
      end
      add_error(:domain_not_found) unless fqdn?(name)
      parse_domain_name(@name)
    end

    # Looks up "name." in DNS. If found, it is a FQDN.
    def fqdn?(name)
      return true unless @dns

      @fqdn = name + '.' if dns(name + '.').valid?(:host)
      @fqdn ? true : false
    end

    def find_fqdn(name)
      DNSCache.instance.dns_config[:search].each do |base|
        full = name + '.' + base
        return full if fqdn?(full)
      end
      name
    end

    ############################################################################
    # Parse/Split Domain Name
    ############################################################################

    # Parses/Splits the domain name into component parts:
    #     subdomains.apex_name.sld.tld
    def parse_domain_name(name)
      sub_apex = parse_tld(name)
      return false if sub_apex == name # parse failed

      if (m = sub_apex.match(/\A(.+)\.(.+)\z/)) # subdomains.apex_name
        @subdomain = m[1]
        @apex_name = m[2]
      else
        @apex_name = sub_apex
      end
      # p [:parse_domain_name, name, @subdomain, @apex_name, @sld, @tld, @tlds]
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
      @tlds = [@sld, @tld].compact.join('.')
      name
    end

    def parse_comment(name)
      if (m = name.match(Regex::COMMENT_PARTS))
        @comment_left  = m[1]
        name           = m[2]
        @comment_right = m[3]
      end
      # if (m = name.match(/\A\((.+?)\)(.+)/)) # (comment)domain.tld
      #   @comment_left = m[1]
      #   name = m[2]
      # end
      # if (m = name.match(/\A(.+)\((.+?)\)\z/)) # domain.tld(comment)
      #   @comment_right = m[2]
      #   name = m[1]
      # end
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

    # Identifies the Email Service Provider (ESP) by  host or MX names
    def find_provider
      return if find_provider_by_host
      return configure_provider(:default) unless dns
      return if find_provider_by_mxers

      configure_provider(:default)
    end

    def find_provider_by_host
      @config.providers.each do |provider, config|
        p [:unf, provider, config] if config.nil?
        if config[:host_match] && matches?(config[:host_match])
          return configure_provider(provider)
        end
      end
      nil
    end

    def find_provider_by_mxers
      # p @name, dns.mx_hosts
      @config.providers.each do |provider, config|
        dns.mx_hosts.each do |mx| # {:host,:ipv4,:ipv6,:preference}
          next if mx[:host] == @name # Same host

          host = Domain.new(mx[:host])
          if host.matches?(config[:host_match])
            return configure_provider(provider)
          end
        end
      end
      nil
    end

    # Updates configuration instance with the given provider settings
    def configure_provider(name) # :nodoc:
      @config.provider(name)
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
