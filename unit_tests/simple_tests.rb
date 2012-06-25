#simple_tests.rb
#Ben Jones
#Summer 2012
#simple_tests.rb: this file contains some basic unit tests. These tests are 
# simple in that they do not need networking support and primarily verify
# helper functions like create_connect
require 'test-unit'
require_relative "../ddosApi.rb"
require 'socket'
require 'thread'


class SimpleTests < Test::Unit::TestCase

  #I have to get a little complicated with the port numbers so that I do not
  # get an address in use error. 
  attr_accessor :server_is_set_up, :port

  @method_name = "Basic unit tests for DDOS API ADPAR"
  
  #class method that runs one time setup methods-> called once before all test
  # functions
  def self.startup
    @@port = 6675
    @@server_port = 6670
    @@server = TCPServer.new('localhost', @@server_port)
    @@listening = Thread.new { @@server.listen}
  end
  #class method to run one time teardown methods-> called at end of all test
  # methods
  def self.shutdown
    @@server.close
    @@listening.exit
  end

  #setup method called before each test method(starts with test_)
  def setup
    @api = DDOS_API.new(1000, 'localhost', @@port)
    @@port += 1
   # @api.config_api('testingConfig.txt')
  end
  #setup method called after each test method(starts with test_)  
  def teardown
    #commented this out because it is now unnecessary
    # @api = nil
    #GC.start
    @api.close_api
    # @server.close
  end

  def test_get_id_by_ip
    #make sure that the first connection opened gets an id of 1
    assert_equal 1, @api.get_id_by_ip('localhost', @@server_port), 'Failed get_id_by_ip 1'
    #make sure that the correct id is returned if available
    assert_equal 1, @api.get_id_by_ip('localhost', @@server_port), 'Failed get_id_by_ip 2'
    #ensure the text 'self' returns an id of -1
    assert_equal -1, @api.get_id_by_ip('self', nil), 'Failed get_id_by_ip 3'
  end

  def test_create_connect
    #assert correct operation
    assert_equal [0, 1], @api.create_connect('localhost', @@server_port), 'Failed create_connect 1'
    #check error handling
#    assert_not_equal [1, 2], @api.create_connect('sdfsdfsd', @@server_port + 1), 'Failed create_connect 2'
#    assert_not_equal [1,2], @api.create_connect('localhost', 'fail'), 'Failed create_connect 3'
  end

end
