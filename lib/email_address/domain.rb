# frozen_string_literal: true
require 'simpleidn'

module EmailAddress

  class Domain
    FORMATS = %i( default localhost ipv4 ipv6 subdomain fqdn )

    attr_accessor :name
    attr_reader :original
    attr_reader :errors
    attr_accessor :format
    attr_accessor :comment_left
    attr_accessor :comment_right
    attr_accessor :subdomain, :apex_name, :sld, :tld, :ip
    attr_accessor :apex_domain, :fqdn, :punycode, :provider

    def initialize(name=nil, config={})
      @errors = []
      @config = config
      if config[:dns_lookup] == :off
        @dns = nil
      else
        @dns = DNSCache::instance
      end
      self.name = name if name
    end

    def dns(name=@name)
      return nil if !@dns || !name
      @dns.lookup(name)
    end

    def name=(name)
      @errors = []
      @original = name
      @subdomain = @apex_name = @sld = @tld = @ip = nil
      @apex_domain = @fqdn = @punycode = nil
      parse(name)
      find_provider
    end

    # The exploded domain data
    def data
      { name: @name, # from the email address
        format: @format,
        comment_left: @comment_left,
        comment_right: @comment_right,
        apex_name: @apex_name, # "example"
        apex_domain: @apex_domain, # example.com
        tld: @tld, # "com"
        sld: @sld, # "co" as in "co.uk"
        tlds: tlds, # sld + tld
        subdomain: @subdomain, # "www"
        ip_address: @ip, # 127.0.0.1 or ::1
        fqdn: @fqdn, # "sub.domain.sld.tld."
        idn: idn?,
        punycode: @punycode, # for IDN
        errors: @errors,
      }
    end

    def inspect
      "<#EmailAddress::Domain "+data.inspect+">"
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
      [@sld, @tld].compact.join(".")
    end

    # true if this is a IDN/International Domain Name
    def idn?
      @punycode =~ /\A^xn--/ || @name =~ /\A^xn--/
    end

    def self.valid?(name, config={})
      new(name,config).valid?
    end

    def valid?
      @errors.count == 0
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
          else
            return true if v && rule == v
          end
        end
        next unless rule.is_a?(String)
        return true if rule.end_with?(".") && @apex_name == rule[0..-2]
        return true if rule.start_with?(".") && @name.end_with?(rule)
        [@name, @punycode, @fqdn, @ip].each do |v|
          return true if v && File.fnmatch?(rule, v)
        end
        return true if ip_matches?(ip, rule)
      end
      false
    end

    private

    def parse(name)
      name = parse_comment(name)
      if name =~ /\A\[IPv6:(.+)\]/i
        @ip = $1.downcase.gsub(/\b0+/,'') # Remove leading zeroes
        @name = "[IPv6:#{@ip}]"
        @format = :ipv6 #@ip == "::1" ? :localhost : :ipv6
        add_error(:no_ip_domain) unless @config[:host_allow_ip]
      elsif name =~ /\A\[(\d{1,3}(\.\d{1,3}){3})\]/ # IPv4
        @ip = $1.gsub(/\b0+([1-9])/,'\1') # Remove leading zeroes
        @name = "[#{@ip}]"
        @format = :ipv4 #@ip == "127.0.0.1" ? :localhost : :ipv6
        add_error(:no_ip_domain) unless @config[:host_allow_ip]
      else
        name = name.gsub(/\s+/,'') if @config[:host_remove_spaces]
        name = fully_qualified_domain_name(name.downcase)
        parse_dns_name(name)
        check_dns if dns
      end
    end

    def parse_dns_name(name)
      @name = name
      if name =~ /[^[:ascii:]]/
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
      if name =~ /\A(.+)\.(\w{3,10})\z/ ||  # (1=children).(2=tld)
        name =~ /\A(.+)\.(\w{1,3})\.(\w\w)\z/ || # (1=children).(2=sld).(3=tld)
        name =~ /\A(.+)\.(\w\w)\z/             # *1.children).(2=tld/2char)

        sub_and_domain, @tld = [$1, $2] # sub+domain, com || co.uk
        @sld, @tld = [$2, $3] if $3

        if sub_and_domain =~ /\A(.+)\.(.+)\z/ # is subdomain? sub.example [.tld]
          @subdomain, @apex_name = $1, $2
        else
          @apex_name = sub_and_domain
        end
        @apex_domain = [@apex_name, @sld, @tld].compact.join('.')
      else
        false
      end
    end

    def fully_qualified_domain_name(name)
      return name if name == 'localhost'
      return name unless @dns

      if dns(name+'.').valid?(:host)
        @fqdn = name + '.'
        return name
      end

      return name unless @config[:allow_partial_fqdn]
      DNSCache.instance.dns_config[:search].each do |base|
        if dns(name+'.'+base+'.').valid?(:host)
          @fqdn = name+'.'+base+'.'
          return name+'.'+base
        end
      end
      add_error(:domain_not_found)

      name
    end

    def parse_comment(name) # :nodoc:
      if name =~ /\A\((.+?)\)(.+)/ # (comment)domain.tld
        @comment_left, name = $1, $2
      end
      if name =~ /\A(.+)\((.+?)\)\z/ # domain.tld(comment)
        name, @comment_right = $1, $2
      end
      name
    end

    def check_dns
      return unless dns
      return if @ip
      unless dns(@fqdn||@name+".").valid?(@config[:dns_lookup] || :mx)
        add_error(:host_unknown, "Unknown Domain or missing MX", @name)
      end
    end

    def find_provider
      #p "------------------------------> " + @name
      #p dns.mx_hosts
      EmailAddress::Config.providers.each do |provider, config|
        if config[:host_match] && self.matches?(config[:host_match])
          return set_provider(provider, config)
        end
        #p [:unf, provider, config]
      end
      return self.set_provider(:default) unless dns

      EmailAddress::Config.providers.each do |provider, config|
        dns.mx_hosts.each do |mx| # {:host,:ipv4,:ipv6,:preference}
          next if mx[:host] == @name # Same host
          host = Domain.new(mx[:host])
          if host.matches?(config[:host_match])
            #p [:mxm, rule, mx]
            return set_provider(provider, config)
          end
        end
      end

      #provider = self.exchangers.provider
      #if provider && provider != :default
      #  p [253, provider]
      #  self.set_provider(provider,
      #    EmailAddress::Config.provider(provider))
      #end

      @provider || set_provider(:default)
    end

    def set_provider(name, provider_config=nil) # :nodoc:
      provider_config ||= EmailAddress::Config.providers[name]
      #p [:set_provider, @name, name, provider_config]
      @config = EmailAddress::Config.all_settings(provider_config, @config)
      @provider = name
    end


    def add_error(message, hint=nil, data=nil)
      #p [:add_error, message, hint, data];
      @valid = false
      @errors << {message: message, hint: hint, data:data}
    end

    ############################################################################
    # Matching
    ############################################################################

    #def mx_matches?(rule)
    #  return false unless @dns
    #  @dns.mx_hosts.each do |mx| # {:host,:ipv4,:ipv6,:preference}
    #    host = Domain.new(mx[:host])
    #    p [:mxm, rule, mx]
    #    return true if host.matches?(rule)
    #    ips = rule.include?(":") ?  mx[:ipv6] : mx[:ipv4]
    #    ips.each do |ip|
    #      return true if DNS.in_cidr?(ip, rule)
    #    end
    #  end
    #  false
    #end

    # True if the host is an IP Address form, and that address matches
    # the passed CIDR string ("10.9.8.0/24" or "2001:..../64")
    def ip_matches?(ip, cidr)
      DNS.in_cidr?(ip, cidr)
    end

  end

end

