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
  def get_data(fib_index, fib, luc_index, luc, id)
    @sem.lock
    if(@fibs[fib_index].nil? or @fibs[fib_index] == fib) and (@lucs[luc_index].nil? or @lucs[luc_index] == luc) then 
      @valid[id] = true
    else 
      @valid[id] = false
    end
  end

  #rec_fail(*backup): will use backup as an array of variables and values that this
  # object will use to pick the computation back up from where it left off
  def rec_fail(data)
    sem.lock
    @fibs = data[0]
    @lucs = data[1]
    @max = data[2]
    sem.unlock
  end

  #compute(nil): compute the next number in the Lucas and Fibonacci sequences
  def compute
    #compute the next number in the Lucas and Fibonnaci sequence
    @sem.lock
    for run in 1..loops do
      @fibs[@max+1] = @fibs[@max] + @fibs[@max -1]
      @lucs[@max+1] = @lucs[@max] + @lucs[@max -1]
      @max += 1
    end
    @sem.unlock
  end

  #latest_seq: this method will return an array with the latest numbers in each
  # sequence and their indices after it has been converted into YAML
  def latest_seq
    data = [@max, @fibs[@max], @lucs[@max]]
    to_send = data.to_yaml
  end
end
