#!/usr/bin/env ruby 

#  Tired of remembering passwords? Hash them! This is a terminal app to
#  simplify generation and copying to clipboard. Passwords are compatible
#  with http://www.hashapass.com
#
# Examples::
#   If you wish to create a password for your gmail account...
#
#     hashapass gmail
#
#   ... and you'll be asked for your master password.
#
# Usage::
#   hashapass [-cphv] something_simple
#
# Options::
# * -c, --confirm       Confirm password
# * -p, --print         Print generated password
# * -h, --help          Displays help message
# * -v, --version       Display the version
#
# Author:: ecin@copypastel.com
# Copyright:: (c) 2009 ecin@copypastel.com. Licensed under the MIT License:
#   http://www.opensource.org/licenses/mit-license.php
# Thanks:: todd werth (http://blog.infinitered.com/entries/show/5) for the skeleton of this command-line app

require 'openssl'
require 'base64'
require 'rdoc/usage'
require 'optparse'
require 'ostruct'

class App

  attr_reader :options

  def initialize(arguments, stdin)
    @arguments = arguments
    @stdin = stdin

    @options = OpenStruct.new
  end

  # Parse options, check arguments, then process the command
  def run

    if parsed_options? && arguments_valid? 
      process_arguments            
      process_command
    else
      output_usage
    end

  end

  protected

  # True if required arguments were provided
  def arguments_valid?
    true if @arguments.length == argv_length 
  end

  # Setup the arguments
  def process_arguments
    @parameter = @arguments.first.chomp
  end

  def output_help
    output_version
    RDoc::usage('usage') #exits app
  end

  def output_usage
    RDoc::usage('usage') # gets usage from comments above
  end

  def output_version
    puts "#{File.basename(__FILE__)} #{version}"
  end

  def process_command


  end

end

module Hashapass

  @@version = '0.2'
  @@argv_length = 1

  attr_accessor :terminal_settings, :parameter, :password

  def version
    @@version
  end
  
  def argv_length
    @@argv_length
  end

  def parsed_options?

    # Specify options
    opts = OptionParser.new 
    opts.on('-v', '--version')    { output_version ; exit 0 }
    opts.on('-h', '--help')       { output_help; exit 0 }
    opts.on('-c', '--confirm')    { @options.confirm = true }
    opts.on('-p', '--print')      { @options.print = true }

    opts.parse!(@arguments) rescue return false

    true      
  end

  def process_command
    # Get current terminal settings to restore later on
    get_terminal_defaults

    # Ask for hashing password
    print 'Password: '

    # Turn off echo in the current terminal to accept a password
    turn_off_echo
    @password = STDIN.gets.chomp!

    # If user wants password confirmation...
    if @options.confirm

      # Let's turn on echo again...
      turn_on_echo

      puts
      print 'Password confirmation: '

      # ... and off again.
      turn_off_echo

      # Get password confirmation...
      password_confirmation = STDIN.gets.chomp!

      # And compare it with previous password input
      unless @password == password_confirmation
        puts
        puts 'Passwords don\'t match, exiting...'
        turn_on_echo
        exit 0
      end
    end

    # Print a newline to be pretty
    puts

    # Restore default terminal settings
    turn_on_echo

    # Generate password...
    hash = hash_password(@parameter, @password)

    # ... and copy it to the clipboard
    copy_to_clipboard(hash)

    # If user wants the password to be displayed...
    if @options.print
      puts "Hashed password: #{hash}"
    end

    # Let the user know what just happened
    puts 'Hashed password copied to clipboard!'

    exit 0
  end

  private

  def hash_password(parameter, password)
    Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, password, parameter))[0..7]
  end

  def get_terminal_defaults
    @terminal_settings = `stty -g`
  end

  def copy_to_clipboard(text)
    Kernel.system("printf #{text} | pbcopy")
  end

  def turn_on_echo
    Kernel.system("stty #{terminal_settings}")
  end

  def turn_off_echo
    Kernel.system('stty -echo')
  end

end
# Create and run the application
app = App.new(ARGV, STDIN)
app.extend Hashapass
app.run
