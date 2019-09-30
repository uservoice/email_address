#encoding: utf-8
require_relative '../test_helper'

class TestStandardAddress < Minitest::Test
  VALID_ADDRESSES = [
    "simple@rubygems.org", # From https://en.wikipedia.org/wiki/Email_address
    "very.common@rubygems.org",
    "disposable.style.email.with+symbol@rubygems.org",
    "other.email-with-hyphen@rubygems.org",
    "fully-qualified-domain@rubygems.org",
    "user.name+tag+sorting@rubygems.org", #(may go to user.name@rubygems.org inbox depending on mail server)
    "x@rubygems.org", #(one-letter local-part)
    "example-indeed@rubygems.org",
#   "admin@mailserver1", # (local domain name with no TLD, although ICANN highly discourages dotless email addresses)
#   "example@s.example", # (see the List of Internet top-level domains)
    %q|" "@rubygems.org|, # (space between the quotes)
    %q|"john..doe"@rubygems.org|, # (quoted double dot)
    "First#Last+TAG@rubygems.org",
    "aasdf-34-.z@rubygems.org",
    %q((left)AZ.az.09.!#$%&'*+-/=?^_`{|}~." (),:;<>@[\\\\\"].."(right)@(left)rubygems.org(right)), # Escaped: [\\\"]
  ]
  VALID_UNICODE_ADDRESSES = [
    %q|ɹᴉɐℲuǝll∀@ɹᴉɐℲuǝll∀.ws|,
  ]
  INVALID_ADDRESSES = [
    %q|Abc.rubygems.org|, # no @ character
    %q|A@b@c@rubygems.org|, # only one @ is allowed outside quotation marks
    %q|a"b(c)d,e:f;g<h>i[j\k]l@rubygems.org|, #  none of the special characters in this local-part are allowed outside quotation marks
    %q|just"not"right@rubygems.org|, # quoted strings must be dot separated or the only element making up the local-part
    %q|this is"not\allowed@rubygems.org|, # spaces, quotes, and backslashes may only exist when within quoted strings and preceded by a backslash
    %q|this\ still\"not\\allowed@rubygems.org|, # even if escaped (preceded by a backslash), spaces, quotes, and backslashes must still be contained by quotes
    %q|1234567890123456789012345678901234567890123456789012345678901234+x@rubygems.org|, # local part is longer than 64 characters
    %q|.user.@gmail.com|, #
    %q|user.@gmail.com|, #
    %q|user..name@rubygems.org|, #
  ]

  def test_parse
    a = EmailAddress.new("(lcl)User+tag(lcr)@(dcl)rubygems.org(dcr)")
    assert_equal "user+tag",    a.local.name
    assert_equal "(lcl)",       a.local.comment_left
    assert_equal "(lcr)",       a.local.comment_right
    assert_equal "rubygems.org", a.domain.name
    assert_equal "dcl",        a.domain.comment_left
    assert_equal "dcr",        a.domain.comment_right
    assert_equal a.valid?,      true
  end

  def test_valid_addresses
    VALID_ADDRESSES.each do |e|
      a = EmailAddress.new(e)
      assert a.valid?, e
    end
  end

  def test_invalid_addresses
    INVALID_ADDRESSES.each do |e|
      a = EmailAddress.new(e)
      assert !a.valid?, e
    end
  end
end
