=begin
testClass.rb
Ben Jones
Spring 2012
testClass.rb: this file contains the definition for a class used to test my ddos
              failover API
=end

class testClass
  #instance variable to determine if I will be computing the fibonacci sequence or
  #primes
  @purpose

  #constants to make purpose definitions easier
  FIB = 1
  PRIME = 2

  #store the largest value that I have computed and that my neighbors have computed
  @largest_rec_seq
  @largest_seq
  @old_seq

  def get_data(data)
    #fixMe-> make sure the yaml method is correct
    @largest_rec_seq = data.to_data
  end

  def compute
    #compute the fibonnacci sequence
    if @purpose == FIB do
        @largest_seq = @old_seq[0] + @old_seq[1]
        @old_seq[0] = @old_seq[1]
        @old_seq[1] = @largest_seq
    end

    #otherwise, compute whether the given fibonacci numbers are relatively prime
    else do
        #fixMe-> find another sequence to use here
