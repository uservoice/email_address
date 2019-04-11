#encoding: utf-8
require_relative '../test_helper'

class TestDNS < Minitest::Test
  GOOD_DOMAIN = "ruby-lang.org"
  UNKNOWN_DOMAIN  = "be3u8erg7ywegknjh.com"

  def test_new
    dns = EmailAddress::DNS.new(GOOD_DOMAIN)
    assert dns.dns_name == GOOD_DOMAIN, "Expected Domain to be used"
  end

  def test_lookup
    EmailAddress::DNS.clear_cache
    dns = EmailAddress::DNS.lookup(GOOD_DOMAIN)
    assert !dns.from_cache, "Expected a fresh object"
    dns = EmailAddress::DNS.lookup(GOOD_DOMAIN)
    assert dns.from_cache, "Expected a cached object"
  end

  def test_mx_hosts
    dns = EmailAddress::DNS.lookup(GOOD_DOMAIN)
    assert dns.mx_hosts.first[:host] =~ /ruby-lang/, "Did not get correct MX"
  end

  def test_valid
    dns = EmailAddress::DNS.lookup(GOOD_DOMAIN)
    assert dns.valid?, "Should have been valid"
    dns = EmailAddress::DNS.lookup(UNKNOWN_DOMAIN)
    assert !dns.valid?, "Should not have been valid"
  end

  def test_dkim_record
    dns = EmailAddress::DNS.lookup("gmail.com")
    dkim = dns.dkim_record("20161025")
    assert dkim[:k] == "rsa"
  end

  def test_spf_record
    dns = EmailAddress::DNS.lookup("gmail.com")
    spf = dns.spf_record
    assert spf =~ /spf1/, "SPF Record not found"
  end

  def test_mx_ip
    dns = EmailAddress::DNS.lookup("gmail.com")
    assert dns.mx_ipv4.first =~ /./, "Missing IPv4"
    assert dns.mx_ipv6.first =~ /:/, "Missing IPv6"
  end

  def test_file_cache
    dns = EmailAddress::DNS.lookup("gmail.com", :dns_cache => :file )
    p dns.mx_ipv4
  end

end
