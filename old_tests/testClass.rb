=begin
testClass.rb
Ben Jones
Spring 2012
testClass.rb: this file contains the definition for a class used to test my ddos
              failover API
=end

require 'yaml.rb'

class TestClass
  #variables to store all the fibonacci and lucas numbers I have computed, along
  # with the maximum number in the sequence computed so far
  @fibs
  @lucs
  @max

  #valid: this array will store a true or false value for each id that has been seen
  # so far
  #count: this variable will store the number of valid communications received
  @valid
  @count

  #semaphore to lock access to sequence of numbers
  @sem
  
  #ddos_api: reference to the ddos api instance for this class
  @ddos_api

  #constructor
  def initialize(ddos_api)
    @ddos_api = ddos_api
    @max = 1
    @fibs = [0, 1]
    @lucs = [2, 1]
    @valid = []
    @count = 0
    @sem = Mutex.new
  end

  #backup: this method will put the object into yaml
  def backup
    @sem.lock
    data = [@max, @fibs, @lucs].to_yaml
    @sem.unlock
    data
  end

  #get_data(*data, int connect_id): method to handle incoming data from the API
  # from the given id. In this objects case, it will just compare that info with
  # the info computed from this server and either set the element for this index
  # to true for valid or false for invalid
  def get_data(data, id)
    index, fib, luc = YAML.load(data)
    @count += 1
#    puts "On id #{id} reveived data: #{data}\n"
#   puts "and vars: index: #{index} fib: #{fib} luc: #{luc}\n"
    @sem.lock
    if((@fibs[index].nil? or @fibs[index] == fib) and (@lucs[index].nil? or @lucs[index] == luc)) then 
      @valid[id] = true
      puts "valid data received in service. This is the (#{@count})th receipt\n"
    else 
      @valid[id] = false
      puts "invalid data received in service. This is the(#{@count})th receipt\n"
    end
    @sem.unlock
  end

  #load_fail(*backup): will use backup as an array of variables and values that this
  # object will use to pick the computation back up from where it left off
  def load_fail(data)
    @sem.lock
    @fibs = data[0]
    @lucs = data[1]
    @max = data[2]
    @sem.unlock
  end

  #compute(nil): compute the next number in the Lucas and Fibonacci sequences
  def compute
    #compute the next number in the Lucas and Fibonnaci sequence
    @sem.lock
    @fibs[@max+1] = @fibs[@max] + @fibs[@max -1]
    @lucs[@max+1] = @lucs[@max] + @lucs[@max -1]
    @max += 1
#    sleep 0.4
    @sem.unlock
  end

  #latest_seq: this method will return an array with the latest numbers in each
  # sequence and their indices after it has been converted into YAML
  def latest_seq
    data = [@max, @fibs[@max], @lucs[@max]]
    to_send = data.to_yaml
  end
end
