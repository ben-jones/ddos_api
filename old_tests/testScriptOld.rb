=begin
test_script.rb
Ben Jones
Spring 2012
test_script.rb: this is a simple script to test my DDOS failover API. The purpose of
                each section will be outlined as I go along

Note: this test script is configured from a text file. This file should be named 
      testSetup.txt and will be the same for every server to configure. It have the 
      following syntax. The first line is the number of valid servers and every line
      after that has a local server ip and name. The failover servers will be
      determined by the API configuration file failover.txt
=end

#include the API and the class that I will use to test the API
require 'ddosApi.rb'
require 'testClass.rb'

#read in the server and failover info from a text file
file = File.open("reindeer.txt","r")
num_servers = file.gets
num_servers.chomp!
num_servers = num_servers.to_i

server_num = 0
valid_input = false
while !valid_input do
  begin
    puts "\nPlease enter the number of this server to configure"
    puts "\nthe DDOS failover API test program 'Chaotic Reindeer'"
    puts "\nThis number will give the line number of the server's"
    puts "\nlocal ip address and port number"
    server_num = gets.to_i
    raise if server_num > num_servers
    else valid_input = true
  rescue
    puts "\nInvalid server number. Please retry\n"
  end
end

#fixMe-> add line to determine ip and port using server_num


#create a new DDOS_API object to handle failovers and configure it
#set the failover timeout to 30 seconds and service_object to an instance of the test
#class. The local ip and port will be set from my configuration file
ddos = DDOS_API.new(30, localhost, 3000, ip, port)
ddos.config_api()


