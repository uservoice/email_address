# frozen_string_literal: true

require 'resolv'
require 'netaddr'
require 'socket'

module EmailAddress

  # Looks up DBS information with caching, and returns to caller
  class DNS
    #include Enumerable

    @@dns_cache = {}

    DEFAULT_CACHE_SIZE=1000
    UNKNOWN_DOMAIN = ""
    DEFAULT_IP = "0.0.0.0"
    DEFAULT_MX = [["example.com", "0.0.0.0", 1]]
    LOOKUP = %i( disabled lru_file_cache custom_cache lru_cache no_cache )

    attr_reader :dns_name

    # Takes an ASCII/Punycode domain name string and the configuration
    # We cache instances here with a LRU Cache up to 100 or value in the
    # EMAIL_ADDRESS_CACHE_SIZE environment variable
    def self.lookup(dns_name, config={})
      @dns_cache ||= {}
      @cache_size ||= config[:dns_cache_size] || ENV['EMAIL_ADDRESS_CACHE_SIZE'].to_i || 1000
      if @dns_cache.has_key?(dns_name)
        o = @dns_cache.delete(dns_name)
        @dns_cache[dns_name] = o # LRU cache, move to end
      elsif @dns_cache.size >= @cache_size
        @dns_cache.delete(@dns_cache.keys.first)
        @dns_cache[dns_name] = new(dns_name, config)
      else
        @dns_cache[dns_name] = new(dns_name, config)
      end
    end

    # Use this to make a non-cached version. Otherwise, use .lookup()
    def initialize(dns_name, config={})
      @dns_name = dns_name
      @config = config
    end

    def valid?
      mxers.count > 0
    end

    # True if the :dns_lookup setting is enabled
    def enabled?
      [:mx, :a].include?(EmailAddress::Config.setting(:host_validation))
    end

    # Returns the IP Address, "0.0.0.0" as defined in the A Record. Do not use
    # this for email; use the MX record lookup instead.
    # Returns DEFAULT_IP if lookups disabled, UNKNOWN_DOMAIN on error
    def ip
      if @_a
        @_a
      elsif @config[:dns_lookup] == :off
        return @_a = DEFAULT_IP
      else
        cache [self.dns_name, 'a'].join(":") do |key|
          @_a = Socket.gethostbyname(self.dns_name)
        rescue SocketError # not found, but could also mean network not work
          @_a = UNKNOWN_DOMAIN
        end
      end
    end

    def mx_records
      if @_mx
        @_mx
      elsif @config[:dns_lookup] == :off
        return @_mx = DEFAULT_MX
      else
        cache [self.dns_name, 'mx'] do |key|
          @_mx = Socket.gethostbyname(self.dns_name)
        rescue SocketError # not found, but could also mean network not work
          @_mx = []
        end
      end
    end

    def dmarc_record
      self.dns_name ? self.txt_hash("_dmarc." + self.dns_name) : {}
    end

    def ptr_record
    end

    # EG: v=spf1 include:spf.ruby-lang.org ?alll
    def spf_record
      txt_hash()
    end

    # A TXT record for _domainkey.example.com with name/key pairs with DKIM signing info
    #    o         "-" All iemail is signed, '~' some email is signed
    #    t         test mode
    #    r         responsible email address
    #    v         DKIM1  (Version)
    #    k         rsa (key type)
    #    p         "..." Signing key
    #
    # EG: v=DKIM1\; k=rsa\; p=a9383... (Sometimes your semicolons must be escaped)
    # See: https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail#Verification
    def dkim_record
      txt_hash("_domainkey")
    end

    private

    def a_records
      dns_records(:a).map {|rec| red.address.to_s }
    end

    # Parses TXT record pairs into a hash
    def txt_hash(subdomain=nil)
      fields = {}
      record = self.txt(subdomain)
      return fields unless record

      record.split(/\s*;\s*/).each do |pair|
        (n,v) = pair.split(/\s*=\s*/)
        fields[n.to_sym] = v
      end
      fields
    end

    # Returns a hash of the domain's DMARC (https://en.wikipedia.org/wiki/DMARC)
    # Returns a contacenation of the TXT records from the host or subhomain,
    # or empty string on error
    def txt(subdomain=nil)
      cache([self.dns_name, subdomain, :txt]) do
				dns_records(:txt).map(&:data).join(" ")
      end
    end

    # Maps simple names into Resolv Library types
    DNS_RECORD_TYPES = {
      a:     Resolv::DNS::Resource::IN::A,
      aaaa:  Resolv::DNS::Resource::IN::AAAA,
      any:   Resolv::DNS::Resource::IN::ANY,
      cname: Resolv::DNS::Resource::IN::CNAME,
      hinfo: Resolv::DNS::Resource::IN::HINFO,
      minfo: Resolv::DNS::Resource::IN::MINFO,
      mx:    Resolv::DNS::Resource::IN::MX,
      ns:    Resolv::DNS::Resource::IN::NS,
      ptr:   Resolv::DNS::Resource::IN::PTR,
      soa:   Resolv::DNS::Resource::IN::SOA,
      txt:   Resolv::DNS::Resource::IN::TXT,
      wks:   Resolv::DNS::Resource::IN::WKS,
    }

    def dns_record_hashes(record_name=:a, subdomain=nil)
      dns_records(record_name, subdomain).map do |rec|
        hash = {}
        rec.instance_variables.each do |n|
          v = rec.instance_variable_get(n)
          hash[n.to_s[1..]] = v.class.name == 'Integer' ? v : v.to_s
        hash
      end
    end

    # Returns: [Resolv::DNS::Resource,...]
    # If a block is passed, it gets each record, and the results of block are returned
    # ips = dns_records(:a).map { |record| a.address.to_s } #=> [ip, ...]
    # ips = dns_records(:txt).map(&:data)
    def dns_records(record_name=:a, subdomain=nil)
      host = subdomain ? [subdomain, self.dns_name].join(".") : self.dns_name
      Resolv::DNS.open do |dns|
        dns.getresources(host, DNS_RECORD_TYPES[record_name.to_sym])
      end
    end

    # Caches a DNS Lookup in a file store (useful for off-line/testing) or a
    # user-provided cache (that saves in memcache/redis/etc.).
    def cache(key, &block)
      key = Array(key).join(":")
      if @config[:dns_cache] == :file
        file_cache(key, block)
      elsif @config[:dns_cache_custom]
        @config[:dns_cache_custom].call(key, block)
      else
        call(key, block)
      end
    end

    # VCR-like File System Caching for testing/performance
    # data = fs_cache_for(domain, 'MX') { request(...) }
    def file_cache(*names, &block)
      if @config[:save_dns_dir]
        fn = File.join(@config[:save_dns_dir], names.join(":"))
        if File.exist?(fn)
          data = JSON.parse(File.read(fn))
        else
          data = block.call
          File.write(fn, JSON.generate(data))
        end
      else
        data = block.call
      end
      data
    end

    # Returns a DNS TXT Record
    def txt(alternate_host=nil)
      Resolv::DNS.open do |dns|
        records = dns.getresources(alternate_host || self.dns_name,
                                   Resolv::DNS::Resource::IN::TXT)
        records.empty? ? nil : records.map(&:data).join(" ")
      end
    end

    # Returns: [["mta7.am0.yahoodns.net", "66.94.237.139", 1], ["mta5.am0.yahoodns.net", "67.195.168.230", 1], ["mta6.am0.yahoodns.net", "98.139.54.60", 1]]
    # If not found, returns []
    # Returns a dummy record when dns_lookup is turned off since it may exists, though
    # may not find provider by MX name or IP. I'm not sure about the "0.0.0.0" ip, it should
    # be good in this context, but in "listen" context it means "all bound IP's"
    def mxers
      return [["example.com", "0.0.0.0", 1]] if @config[:dns_lookup] == :off
      @mxers ||= Resolv::DNS.open do |dns|
        ress = dns.getresources(@host, Resolv::DNS::Resource::IN::MX)
        records = ress.map do |r|
          begin
            if r.exchange.to_s > " "
              [r.exchange.to_s, IPSocket::getaddress(r.exchange.to_s), r.preference]
            else
              nil
            end
          rescue SocketError # not found, but could also mean network not work or it could mean one record doesn't resolve an address
            nil
          end
        end
        records.compact
      end
    end

    # Returns Array of domain names for the MX'ers, used to determine the Provider
    def domains
      @_domains ||= mxers.map {|m| EmailAddress::Host.new(m.first).domain_name }.sort.uniq
    end

    # Returns an array of MX IP address (String) for the given email domain
    def mx_ips
      return ["0.0.0.0"] if @config[:dns_lookup] == :off
      mxers.map {|m| m[1] }
    end

    # Simple matcher, takes an array of CIDR addresses (ip/bits) and strings.
    # Returns true if any MX IP matches the CIDR or host name ends in string.
    # Ex: match?(%w(127.0.0.1/32 0:0:1/64 .yahoodns.net))
    # Note: Your networking stack may return IPv6 addresses instead of IPv4
    # when both are available. If matching on IP, be sure to include both
    # IPv4 and IPv6 forms for matching for hosts running on IPv6 (like gmail).
    def matches?(rules)
      rules = Array(rules)
      rules.each do |rule|
        if rule.include?("/")
          return rule if self.in_cidr?(rule)
        else
          self.each {|mx| return rule if mx[:host].end_with?(rule) }
        end
      end
      false
    end

    # Given a cidr (ip/bits) and ip address, returns true on match. Caches cidr object.
    def in_cidr?(cidr)
      if cidr.include?(":")
        c = NetAddr::IPv6Net.parse(cidr)
        return true if mx_ips.find do |ip|
          next unless ip.include?(":")
          rel = c.rel NetAddr::IPv6Net.parse(ip)
          !rel.nil? && rel >= 0
        end
      elsif cidr.include?(".")
        c = NetAddr::IPv4Net.parse(cidr)
        return true if mx_ips.find do |ip|
          next if ip.include?(":")
          rel = c.rel NetAddr::IPv4Net.parse(ip)
          !rel.nil? && rel >= 0
        end
      end
      false
    end
    end
  end
