#encoding: utf-8
require_relative '../test_helper'

class TestStandardAddress < Minitest::Test
  VALID_ADDRESSES = [
    "simple@example.com", # From https://en.wikipedia.org/wiki/Email_address
    "very.common@example.com",
    "disposable.style.email.with+symbol@example.com",
    "other.email-with-hyphen@example.com",
    "fully-qualified-domain@example.com",
    "user.name+tag+sorting@example.com", #(may go to user.name@example.com inbox depending on mail server)
    "x@example.com", #(one-letter local-part)
    "example-indeed@strange-example.com",
    "admin@mailserver1", # (local domain name with no TLD, although ICANN highly discourages dotless email addresses)
    "example@s.example", # (see the List of Internet top-level domains)
    %q|" "@example.org|, # (space between the quotes)
    %q|"john..doe"@example.org|, # (quoted double dot)
    "First#Last+TAG@example.com",
    "aasdf-34-.z@example.com",
    %q((left)AZ.az.09.!#$%&'*+-/=?^_`{|}~." (),:;<>@[\\\\\"].."(right)@(left)example.com(right)), # Escaped: [\\\"]
  ]
  VALID_UNICODE_ADDRESSES = [
    %q|ɹᴉɐℲuǝll∀@ɹᴉɐℲuǝll∀.ws|,
  ]
  INVALID_ADDRESSES = [
    %q|Abc.example.com|, # no @ character
    %q|A@b@c@example.com|, # only one @ is allowed outside quotation marks
    %q|a"b(c)d,e:f;g<h>i[j\k]l@example.com|, #  none of the special characters in this local-part are allowed outside quotation marks
    %q|just"not"right@example.com|, # quoted strings must be dot separated or the only element making up the local-part
    %q|this is"not\allowed@example.com|, # spaces, quotes, and backslashes may only exist when within quoted strings and preceded by a backslash
    %q|this\ still\"not\\allowed@example.com|, # even if escaped (preceded by a backslash), spaces, quotes, and backslashes must still be contained by quotes
    %q|1234567890123456789012345678901234567890123456789012345678901234+x@example.com|, # local part is longer than 64 characters
    %q|.user.@gmail.com|, #
    %q|user.@gmail.com|, #
    %q|user..name@example.com|, #
  ]

  def test_parse
    a = EmailAddress.new("(lcl)User+tag(lcr)@(dcl)example.com(dcr)")
    assert_equal "User+tag",    a.local.name
    assert_equal "(lcl)",       a.local.comment_left
    assert_equal "(lcr)",       a.local.comment_right
    assert_equal "example.com", a.domain.name
    assert_equal "(dcl)",       a.domain.comment_left
    assert_equal "(dcr)",       a.domain.comment_right
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
