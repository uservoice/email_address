# frozen_string_literal: true

require 'resolv'
require 'netaddr'
require 'socket'
require 'singleton'

module EmailAddress

  class DNSCache
    include Singleton
    DEFAULT_CACHE_SIZE=1000
    attr_reader :from_cache

    def initialize(config={})
      @semaphore = Mutex.new
      @size = (config[:dns_cache_size] || ENV['EMAIL_ADDRESS_CACHE_SIZE'] || DEFAULT_CACHE_SIZE).to_i
      @cache = {}
    end

    # Takes an ASCII/Punycode domain name string and the configuration
    # We cache instances here with a LRU Cache up to 100 or value in the
    # EMAIL_ADDRESS_CACHE_SIZE environment variable
    def lookup(dns_name, config={})
      dns = nil
      @from_cache = false
      @semaphore.synchronize do
        if @cache.has_key?(dns_name)
          dns = @cache.delete(dns_name)
          @cache[dns_name] = dns # LRU cache, move to end
          @from_cache = true
        elsif @cache.size >= @size
          @cache.delete(@cache.keys.first)
          dns = @cache[dns_name] = DNS.new(dns_name, config)
        else
          dns = @cache[dns_name] = DNS.new(dns_name, config)
        end
      end
      dns
    end

    def clear
      @semaphore.synchronize do
        @cache = {}
      end
    end

  end

  # Looks up DBS information with caching, and returns to caller
  class DNS
    DEFAULT_CACHE_SIZE=1000
    UNKNOWN_HOST = ""
    DEFAULT_IP = "0.0.0.0"
    DEFAULT_MX = [["example.com", "0.0.0.0", 1]]
    LOOKUP = %i( off file_cache custom_cache no_cache )

    attr_reader :dns_name
    # Use this to make a non-cached version. Otherwise, use .lookup()
    def initialize(dns_name, config={})
      @dns_name = dns_name
      @config = config
      @semaphore = Mutex.new
    end

    def valid?
      mx_records.count > 0
    end

    # True if the :dns_lookup setting is enabled
    #def enabled?
    #  [:mx, :a].include?(EmailAddress::Config.setting(:host_validation))
    #end

    # Returns the IP Address, "0.0.0.0" as defined in the A Record. Do not use
    # this for email; use the MX record lookup instead.
    # Returns DEFAULT_IP if lookups disabled, UNKNOWN_HOST on error
    def ip
      if @_a
        @_a
      elsif @config[:dns_lookup] == :off
        return @_a = DEFAULT_IP
      else
        @_a = host_ip(self.dns_name)
      end
    end

    def mx_ipv4
      mx_hosts.map {|mx| mx[:ipv4] }
    end

    def mx_ipv6
      mx_hosts.map {|mx| mx[:ipv6] }
    end

    def mx_hosts
      hosts = []
      mx_records.each do |mx|
        host = mx.exchange.to_s
        if host > " "
          hosts << {host:host,
                    ipv4: a_record,
                    ipv6: aaaa_record,
                    preference: mx.preference}
        end
      end
      hosts
    end

    def dmarc_record
      txt_hash("_dmarc")
    end

    #def ptr_record
    #end

    # EG: v=spf1 include:spf.ruby-lang.org ?alll
    def spf_record
      txt_records.find {|r| r =~ /v=spf1/ }
    end

    # A TXT record for _domainkey.example.com with name/key pairs with DKIM signing info
    # See: https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail#Verification
    # Selector is the DKIM s=xxx value from the Email headers and should find
    # the DKIM key in $selector._domainkey.$dns_name in the TXT record
    def dkim_record(selector)
      txt_hash(selector+"._domainkey")
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
          return rule if in_cidr?(rule)
        else
          mx_hosts.each  {|mx| return rule if mx[:host].end_with?(rule) }
        end
      end
      false
    end

    #def self.clear_file_cache(max_days=2)
    #  dir = @config[:dns_cache_dir] || "/tmp"
    #  p dir
    #end

    private

    def host_ip(host)
      return DEFAULT_IP if @config[:dns_lookup] == :off
      cache(host, :ip) do
        begin
          IPSocket::getaddress(host)
        rescue SocketError # not found, but could also mean network not work or it could mean one record doesn't resolve an address
          DEFAULT_IP # UNKNOWN_HOST
        end
      end
    end

    def mx_records
      if @_mx
        @_mx
      elsif @config[:dns_lookup] == :off
        DEFAULT_MX
      else
        @_mx = dns_records(:mx).sort {|a,b| a.preference <=> b.preference }
      end
    end

    def a_record
      dns_records(:a).map {|rec| rec.address.to_s }.first
    end

    def aaaa_record
      dns_records(:aaaa).map {|rec| rec.address.to_s }.first
    end

    # Parses TXT record pairs into a hash
    def txt_hash(subdomain=nil)
      fields = {}
      record = txt(subdomain)
      return fields unless record

      record.split(/\s*;\s*/).each do |pair|
        (n,v) = pair.split(/\s*=\s*/)
        fields[n.to_sym] = v
      end
      fields
    end

    # Returns a contacenation of the TXT records from the host or subhomain,
    def txt(subdomain=nil, joiner=" ")
      txt_records(subdomain).join(joiner)
    end

    # Returns an array of TXT.data fields
    def txt_records(subdomain=nil)
      @txt_cache ||= {}
      if @txt_cache.has_key?(subdomain)
        @txt_cache[subdomain]
      elsif @config[:dns_lookup] == :off
        return ""
      else
        @txt_cache[subdomain] = dns_records(:txt, subdomain).map(&:data)
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
    end

    # Returns: [Resolv::DNS::Resource,...]
    # If a block is passed, it gets each record, and the results of block are returned
    # ips = dns_records(:a).map { |record| a.address.to_s } #=> [ip, ...]
    # ips = dns_records(:txt).map(&:data)
    def dns_records(record_name=:a, subdomain=nil, &block)
      return [] if @config[:dns_lookup] == :off
      host = subdomain ? [subdomain, self.dns_name].join(".") : self.dns_name
      cache(host, record_name, block) do
        Resolv::DNS.open do |dns|
          dns.getresources(host, DNS_RECORD_TYPES[record_name.to_sym])
        end
      end
    end

    # Caches a DNS Lookup in a file store (useful for off-line/testing) or a
    # user-provided cache (that saves in memcache/redis/etc.).
    def cache(*keys, &block)
      key = keys.join(":")
      @semaphore.synchronize do
        if @config[:dns_cache] == :file
          file_cache(key, &block)
        elsif @config[:dns_cache_custom]
          @config[:dns_cache_custom].call(key, &block)
        else
          block.call(key)
        end
      end
    end

    # VCR-like File System Caching for testing/performance
    # data = file_cache(domain, 'MX') { request(...) }
    def file_cache(*names, &block)
      dir = @config[:dns_cache_dir] || "/tmp"
      fn = File.join(dir, "email_address:dns:"+names.join(":"))
      if File.exist?(fn)
        data = Marshal.load(File.read(fn))
      else
        data = block.call
        p [:file_cache, data]
        File.write(fn, Marshal.dump(data))
      end
      data
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

    # Given a cidr (ip/bits) and ip address, returns true on match. Caches cidr object.
    def in_cidr?(cidr)
      if cidr.include?(":")
        c = NetAddr::IPv6Net.parse(cidr)
        return true if mx_ipv6.find do |ip|
          next unless ip.include?(":")
          rel = c.rel NetAddr::IPv6Net.parse(ip)
          !rel.nil? && rel >= 0
        end
      elsif cidr.include?(".")
        c = NetAddr::IPv4Net.parse(cidr)
        return true if mx_ipv4.find do |ip|
          next if ip.include?(":")
          rel = c.rel NetAddr::IPv4Net.parse(ip)
          !rel.nil? && rel >= 0
        end
      end
      false
    end
  end
end
