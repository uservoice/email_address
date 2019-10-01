#encoding: utf-8
require_relative '../test_helper'

class TestDNS < Minitest::Test
  GOOD_DOMAIN = "rubygems.org"
  UNKNOWN_DOMAIN  = "be3u8erg7ywegknjh.com"
  DNS = EmailAddress::DNSCache.instance # Save typing

  def test_new
    dns = EmailAddress::DNS.new(GOOD_DOMAIN)
    assert dns.dns_name == GOOD_DOMAIN, "Expected Domain to be used"
  end

  def test_lookup
    DNS.clear
    DNS.lookup(GOOD_DOMAIN)
    assert !DNS.from_cache, "Expected a fresh object"
    DNS.lookup(GOOD_DOMAIN)
    assert DNS.from_cache, "Expected a cached object"
  end

  def test_mx_hosts
    dns = DNS.lookup(GOOD_DOMAIN)
    assert dns.mx_hosts.first[:host] =~ /mailgun/, "Did not get correct MX"
  end

  def test_valid
    dns = DNS.lookup(GOOD_DOMAIN)
    assert dns.valid?, "Should have been valid"
    dns = DNS.lookup(UNKNOWN_DOMAIN)
    assert !dns.valid?, "Should not have been valid"
  end

  def test_dkim_record
    dns = DNS.lookup("gmail.com")
    dkim = dns.dkim_record("20161025")
    assert dkim[:k] == "rsa"
  end

  def test_spf_record
    dns = DNS.lookup("gmail.com")
    spf = dns.spf_record
    assert spf =~ /spf1/, "SPF Record not found"
  end

  def test_mx_ip
    dns = DNS.lookup("gmail.com")
    assert dns.mx_ipv4.first =~ /./, "Missing IPv4"
    assert dns.mx_ipv6.first =~ /:/, "Missing IPv6"
  end

  def test_file_cache
    dns = DNS.lookup("gmail.com", :dns_cache => :file )
    assert dns.mx_ipv4.size > 0
  end

end
