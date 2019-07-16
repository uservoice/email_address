# encoding: UTF-8
require_relative '../test_helper'


class TestDomain < MiniTest::Test
  DOMAIN = EmailAddress::Domain # Save keystrokes

  def test_domain
    a = DOMAIN.new("ruby-lang.org")
    assert_equal "ruby-lang.org", a.name
    assert_equal "ruby-lang.org", a.apex_domain
    assert_equal "ruby-lang", a.apex_name
    assert_equal "org", a.tld
    assert_equal "ruby-lang.org.", a.fqdn
    assert_nil   a.subdomain
  end

  #def test_dns_enabled
  #  a = DOMAIN.new("example.com")
  #  assert_instance_of TrueClass, a.dns_enabled?
  #  old_setting = EmailAddress::Config.setting(:host_validation)
  #  EmailAddress::Config.configure(host_validation: :off)
  #  assert_instance_of FalseClass, a.dns_enabled?
  #  EmailAddress::Config.configure(host_validation: old_setting)
  #end

  def test_foreign_host
    a = DOMAIN.new("my.yahoo.co.jp")
    assert_equal "my.yahoo.co.jp", a.name
    assert_equal "yahoo.co.jp", a.apex_domain
    assert_equal "yahoo", a.apex_name
    assert_equal "co", a.sld
    assert_equal "jp", a.tld
    assert_equal "co.jp", a.tlds
    assert_equal "my", a.subdomain
  end

  def test_ip_host
    a = DOMAIN.new("[127.0.0.1]")
    assert_equal "[127.0.0.1]", a.name
    assert_equal "127.0.0.1", a.ip
  end

  def test_idn
    a = DOMAIN.new("å.com")
    assert_equal "xn--5ca.com", a.punycode
    a = DOMAIN.new("xn--5ca.com", host_encoding: :unicode)
    assert_equal "å.com", a.name
  end

  def test_provider
    a = DOMAIN.new("my.yahoo.co.jp")
    assert_equal :yahoo, a.provider
    a = DOMAIN.new("ruby-lang.org")
    assert_equal :default, a.provider
  end

  def test_dmarc
    d = DOMAIN.new("yahoo.com").dns.dmarc_record
    assert_equal 'reject', d[:p]
    d = DOMAIN.new("example.com").dns.dmarc_record
    assert_equal true, d.empty?
  end

  def test_ipv4
    h = DOMAIN.new("[127.0.0.1]", host_allow_ip:true, host_local:true)
    assert_equal "127.0.0.1", h.ip
    assert_equal true, h.valid?
  end

  def test_ipv6
    h = DOMAIN.new("[IPv6:::1]", host_allow_ip:true, host_local:true)
    assert_equal "::1", h.ip
    assert_equal true, h.valid?
  end

  def test_comment
    h = DOMAIN.new("(oops)gmail.com")
    assert_equal 'gmail.com', h.to_s
    assert_equal 'oops', h.comment_left
    h = DOMAIN.new("gmail.com(oops)")
    assert_equal 'gmail.com', h.to_s
    assert_equal 'oops', h.comment_right
  end

  def test_matches
    h = DOMAIN.new("yahoo.co.jp")
    assert ! h.matches?("gmail.com")
    assert 'yahoo.co.jp', h.matches?("yahoo.co.jp")
    assert '.co.jp', h.matches?(".co.jp")
    assert '.jp', h.matches?(".jp")
    assert 'yahoo.', h.matches?("yahoo.")
    assert 'yah*.jp', h.matches?("yah*.jp")
  end

  #def test_regexen
  #  assert "asdf.com".match EmailAddress::Host::CANONICAL_HOST_REGEX
  #  assert "xn--5ca.com".match EmailAddress::Host::CANONICAL_HOST_REGEX
  #  assert "[127.0.0.1]".match EmailAddress::Host::STANDARD_HOST_REGEX
  #  assert "[IPv6:2001:dead::1]".match EmailAddress::Host::STANDARD_HOST_REGEX
  #  assert_nil "[256.0.0.1]".match(EmailAddress::Host::STANDARD_HOST_REGEX)
  #end

  def test_hosted_service
    #assert EmailAddress.valid?('test@jiff.com', dns_lookup: :mx)
    assert ! EmailAddress.valid?('test@gmail.com', dns_lookup: :mx)
  end

  def test_yahoo_bad_tld
    assert ! DOMAIN.valid?('test@yahoo.badtld')
    assert ! DOMAIN.valid?('test@yahoo.wtf') # Registered, but MX IP = 0.0.0.0
  end

  def test_bad_formats
    assert ! DOMAIN.new('ya  hoo.com').valid?
    assert DOMAIN.new('ya  hoo.com', host_remove_spaces:true).valid?
  end

  def test_errors
    assert DOMAIN.new("yahoo.com").errors.count==0
    #assert DOMAIN.new("example.com").errors, "This domain is not configured to accept email"
    #assert DOMAIN.new("yahoo.wtf").errors, "Domain name not registered"
    #assert_nil DOMAIN.new("ajsdfhajshdfklasjhd.wtf", host_validation: :syntax).error
    #assert DOMAIN.new("ya  hoo.com", host_validation: :syntax).errors, "Invalid Domain Name"
    #assert DOMAIN.new("[127.0.0.1]").errors, "IP Addresses are not allowed"
    #assert DOMAIN.new("[127.0.0.666]", host_allow_ip:true).errors, "This is not a valid IPv4 address"
    #assert DOMAIN.new("[IPv6::12t]", host_allow_ip:true).errors, "This is not a valid IPv6 address"
  end
end
