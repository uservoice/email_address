# frozen_string_literal: true

require 'simpleidn'

module EmailAddress
  # *Email Address Correction Feature*
  #
  # These correction may not be accurate in all cases.
  # A "Did you mean" prompt would be useful in an interactive mode.
  module AddressCorrection
    # This function takes an email address string and a correction level,
    #
    #   * 0 => Perform no correction
    #   * 1 => Perform basic correction
    #   * 2 => Perform typo corrections
    #   * 3 => Perform well-known domain/tld corrections
    #
    # Takes an email address from incoming data and attempts to sanatize and
    # perform corrections.
    def correct_address(address, level = null)
      level ||= @config[:correction_level] || 0
      return address if level < 1

      address = correct_address_level_1(address)
      address = correct_address_level_2(address) if level > 1
      address = correct_address_level_3(address) if level > 2

      address
    end

    # Perform basic corrections
    def correct_address_level_1(address)
      address.sub!(/^.*\<(.+)\>.*/, '\1') # Header format: name <email>
      address.gsub!(/\(.*?\)/, '') # Comments
      address.gsub!(/\s+/, '') # fold_white_space(address)
      address = transform_case(address)
      address.sub!(/\W+$/, '') # Trailing noise
      address.gsub!(',', '.') # Commas -> Period
      address.gsub!(/\.+/, '.') # Multiple Periods
      address.gsub!(/\.+$/, '') # Trailing Periods
    end

    # Perform typo correction
    def correct_address_level_2(address)
      address.gsub!(/\w+/, '') # remove white space
      address.sub!(/^(.+)[@=\#\!~\$]([\w\-\.]+?)$/, '\1@\2') # u[~!@#$]domain
      address += '.com' if address =~ /@(yahoo|aol|hotmail|gmail|outlook)$/
      address.sub!(/\.(c|con|cpn|vom|opm|ocm|cmo)$/, '.com') # .com Typo
      address.sub!(/\@(\w+)(com|net|org)$/, '@\1.\2') # gmailcom
      address.sub!(/\.(n+(e+t*)?)$/, '.net') # .net garbled
      address.sub!(/\.(c+o+m+)$/, '.com') # .com garbled
    end

    # Perform well-known domain/tld corrections
    def correct_address_level_3(address)
      address.sub!(/\@y[aho]{3,7}\b/, '@yahoo') # Mispell yahoo
      address.sub!(/\@g[mn][ail]{0,7}\b/, '@gmail') # Mispell gmail
      address.sub!(/\@ou[tlok]{4,7}\b/, '@outlook') # Mispell gmail
      address.sub!(/\@ao+l+\b/, '@aol') # Mispell aol
      address.sub!(/\@([\w\-]+)$/, '@\1.com')
      address
    end
  end
end
