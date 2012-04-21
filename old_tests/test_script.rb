=begin 
 test_script.rb
 Ben Jones
 test_script.rb: this file contains Ruby code to test my DDOS API. The tests to run
  may be selected below and any configuration files beyond those necessary for the
  API will be listed here
=end

#add in the code for the API and test class
require "#{Dir.pwd}/ddosApi.rb"
require "#{Dir.pwd}/testClass.rb"

#send the user info about whats happening
puts "\nWelcome to the Test Script for the DOSR(Denial Of Service Recovery) API\n"
puts "Please provide input when necessary to continue testing the API\n"

#select the test to run
puts "Please select the number of a test to run, in the range 1 to 6\n"
input = gets
test_select = input.to_i
case test_select
#test 1: this is just normal operation with servers sending data back and forth.
# In part A, the servers will send information to each other at intervals that the
#  test_script user specifies. 
# In part B, the servers will not send each other any information, and will test
#  the basic functionality of the send_alive and proc_alive methods
when 1
  puts "Running test 1: Normal Operation between servers without failover\n"
  
  #get network info for this server and the remote server
  puts "\nPlease enter the ip address of this machine: "
  local_ip = gets.chomp
  puts "Please enter the port number on which the connection will be operating: "
  local_port = gets.to_i
  puts "Please enter the ip address of the other server: "
  remote_ip = gets.chomp
  puts "Please enter the port number of the other server: "
  remote_port = gets.to_i

  #get general info for this test
  puts "Please enter the interval to wait between sending data between machines\n"
  puts "The interval should be in units of seconds: "
  interval = gets.to_i
  puts "Please enter the failover timeout for this session in seconds: "
  timeout = gets.to_i



  #create an instance of the API and the service object
  api = DDOS_API.new(timeout, local_ip, local_port)
  service = TestClass.new(api)
  api.set_service_object = service


  #open a connection with the command server and wait for the start command
#  command = TCPSocket.new('localhost', 10000)
#  while wait.nil? and wait[0].gets != "start" do
#    wait = select(command, nil, nil, 1)
#  end
  
  #Part A: have servers send data back and forth at a rate that the user specifies
  # try to run this for 500 iterations
  puts "\n\nStarting Test 1 Part A: basic test of ability to send and receive data\n\n"
  for run in 1..10 do
    #have the service compute the next 2 numbers in each sequence
    service.compute
    service.compute
    sleep interval
    #wait for the interval amount of seconds
    #sleep interval
    #send the latest elements in the sequence to the other server
    #Note: I could send data from inside the TestClass instance by calling methods
    # on the reference to the same api instance
    #on the first run create the connection
    if run == 1 then
      id =  api.send_data(remote_ip, remote_port, service.latest_seq)
    #on later runs just use the previous id to avoid creating new connections
    else
      api.send_data(id, service.latest_seq)
    end
  end

  #sleep here to make sure we receive of the other server's data
  sleep 3
  #Ensure that the API is still alive and functioning correctly
  if api.still_alive then
    puts "\n\nAPI is still alive and working and successfully passed Test 1 Part A\n"
    puts "This means that the servers were able to communicate successfully when\n"
    puts "no failover logic was used\n"
    puts "\nThe test parameters were: \n"
    puts "Local address: #{local_ip} local port: #{local_port}\n" 
    puts "Remote address: #{remote_ip} remote port: #{remote_port}\n" 
    puts "Interval(in seconds): #{interval}\n"
    puts "Timeout(in seconds): #{timeout}\n"
#    puts "\n\nNow moving on to Test 1 Part B\n"
  
  #otherwise, print an error message
  else
    puts "\n\nTest 1 Part A failed: basic test of ability to send and receive data\n"
    puts "This means that the servers could not establish basic connectivity in\n"
    puts "the given time limit."
    puts "\nThe test parameters were: \n"
    puts "Local address: #{local_ip} local port: #{local_port}\n" 
    puts "Remote address: #{remote_ip} remote port: #{remote_port}\n" 
    puts "Interval(in seconds): #{interval}\n"
    puts "Timeout(in seconds): #{timeout}\n"
    raise "Test 1 A Fail"
  end
  #now move onto Test 1 Part B: a basic test of the proc_alive and send_alive 
  # methods
  puts "Starting Test 1 Part B: basic test of the proc_alive and send_alive\n"
  puts "methods. This test will have the service do nothing and just wait.\n"
  puts "After timeout seconds, the servers should start exchanging messages\n"
  puts "querying the other server's status. The same settings will be used\n"
  puts "from part A.\n"
  for run in 1..5 do
    #if the local server or the remote server is dead, then issue an error message
    if !api.still_alive or !api.check_connect_alive(remote_ip, remote_port) then
      puts "Test 1 Part B failed on run: #{run} "
      puts "This was a basic test of send_alive and proc_alive methods\n"
      puts "This means that the servers were unable to successfully communicate\n"
      puts "their statuses to one another in the time given\n"
      puts "\nThe test parameters were: \n"
      puts "Local address: #{local_ip} local port: #{local_port}\n" 
      puts "Remote address: #{remote_ip} remote port: #{remote_port}\n" 
      puts "Interval(in seconds): #{interval}\n"
      puts "Timeout(in seconds): #{timeout}\n"
      raise "Test 1 B Fail"
    end
    sleep timeout
  end
  
  puts "Test 1 Part B has completed successfully."
  puts "This was a basic test of send_alive and proc_alive methods\n"
  puts "This means that the servers were able to successfully communicate\n"
  puts "their statuses to one another in the time given\n"
  puts "\nThe test parameters were: \n"
  puts "Local address: #{local_ip} local port: #{local_port}\n" 
  puts "Remote address: #{remote_ip} remote port: #{remote_port}\n" 
  puts "Interval(in seconds): #{interval}\n"
  puts "Timeout(in seconds): #{timeout}\n"
else
  puts "Invalid testing option\n"
end




