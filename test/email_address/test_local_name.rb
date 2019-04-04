#encoding: utf-8
require_relative '../test_helper'

class TestUser < Minitest::Test
  INVALID_USER = %w(
    -asdfasf@ruby-lang.org
  )
  # [\w.-!#$%&'*+=?^`{|}]+
  VALID_FREE = %w( sdf sdf
    allen@ruby-lang.org
  )
  # (\w+ [.-!#$%&'*+=?^`{|})]+
  VALID_LOOSE = %w( sdf sdf
    allen@ruby-lang.org
  )
  # (\w+ [.-'+/)]+)+
  VALID_NORMAL = %w( sdf sdf
    allen@ruby-lang.org
  )
  # \w+ ([.-'+] \w+)+
  VALID_STRICT = %w( sdf sdf
    allen@ruby-lang.org
  )


  def test_valid_addresses
    VALID_ADDRESSES.each do |e|
      #puts "------------------"
      #puts e
      a = EmailAddress.standard(e)
      assert_equal e, a.valid? ? e : a.errors
    end
  end

  def test_invalid_addresses
    INVALID_ADDRESSES.each do |e|
      #puts "------------------"
      #puts e
      a = EmailAddress.standard(e)
      assert_equal e, a.valid? ? a.data : e
    end
  end
end
