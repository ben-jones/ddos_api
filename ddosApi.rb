=begin
  ddosApi.rb
  Ben Jones
  Spring 2012
  ddosApi.rb: this is a basic API to implement a failover in the case of a DDOS
    attack. This API does not implement DDOS detection per say, but examines the
    time between communications from other servers. The API essentially routes all
    traffic betweent the local server and other servers. More information on
    implementation details may be found throughout the code.
  contents: this file contains the DDOS_API class and all of its necessary code
=end

#I will need to methods from net/http and socket
require 'net/http'
require 'socket'
require 'timeout.rb'

class DDOS_API  

  #main ddos functions
  public
  
  #use this alias to point to the object on the server that is processing data
  @fail_object

  #sockets to send and receive data and failover the server
  @failover_connnect
  @send_connections
  @receive_connection

  #this class variable stores the local ip 
  @local_ip
  @local_port

  #this timestamp records the last time that data was received
  @last_data_received

  #this thread ensures that we are not in a ddos scenario
  @timeout_thread
  
  #this constant stores the amount of time to wait for new data before failing over
  @failover_timeout

  #class variable to store the array of backups
  @backups

  #use ints to store the type of connection
  SEND = 1
  RECEIVE = 2
  BOTH = 3

  #here are some basic accessor methods
  def get_failover_connection
    @failover_connect
  end
  def get_failover_
    @failover_timeout
  end
  
  
  #these functions are the actual meat of the API
  
  #use the constructor to initialize attributes that dont require processing
  def initialize(failover_timeout, local_ip, local_port, fail_object)
    #set the failover timeout to failover_timeout
    @failover_timeout = failover_timeout

    #set the incoming connection information
    @local_ip = local_ip
    @local_port = local_port

    #set @fail_object up as a reference to the service's object
    @fail_object
  end

  #config_api: will read in the ip address of the next server to failover to and
  #store the socket in failover_connect
  #Note: this method should be called before using the rest of the API
  def config_api(failover_filename="failover.txt")
    #then read in the failover data from a file
    failover = File.open(failover_filename,"r")

    #use a flag to see if the failover ip is set inside this loop
    failover_socket_set = false

    #now iterate over each line and find the next failover ip and port from the file
    while line = failover.gets do
      puts line
      line.chomp!
      #turn the input into integers and if it is a hostname, then just return the
      #string
      ip, port = line.split(" ") do |string|
        begin
          string.to_i
          rescue
            string
        end
      end

      #if the last ip read was the ip and of this server, then select the next port
      #and ip. If this is the end of the file, then rewind to the beginning and use
      #the first connection listed in the text document
      if(ip == @local_ip) then
          line = failover.gets
          if(line == nil) then
              failover.rewind
              line = failover.gets
          end
          line.chomp!
          ip, port = line.split(" ")
          failover_socket_set = true
          break
      end
    end

    #if the local address could not be found, then use the first entry in the file
    if(failover_socket_set == false) then
      failover.rewind
      line = failover.gets
      line.chomp!
      ip, port = line.split(" ")
    end
    
    #close the file
    failover.close

    #now set up a thread to determine if a failover is needed
    @timeout_thread = Thread.new(Time.now) {|time| ddos_check(time) }
    
    #set/ return the value of the failover connection
    @failover_connect = ip, port
  end
    
    
  #send_data: this function will send proc_data to the given connection.
  #this is yet another overloaded version of the send_data method. This version will
  #create a new ip_address and make sure that the connection id is returned to the
  #calling function
  def send_data(ip_address, port_num, *proc_data)
    connection = TCPSocket.new(ip_address, port_num)
    connect_index = @send_connections.length
    @send_connections << connection
    self.send_data(connect_index, proc_data)
  end
  #this function just looks up the connection info via its connectionIndex and then
  #sends the data
  def send_data(connect_index, *proc_data)
    #if this server has been "killed", then dont accept any more connections
    return nil unless @kill

    #I have included some basic error handling here
    begin
      raise ArgumentError, "No argument" if connect_index.nil?
      raise ArgumentError, "Invalid Connection index" if (connect_index < 0 || connect_index > @send_connections.length)
      rescue => err
        puts err
      return connect_index
    end
    
    #now just send the data
    @send_connections[connect_index].puts proc_data
    
    #and finally return connect_index
    return connect_index
  end


  #receive_data: will receive data from a server and pass it along. 
  def receive_data(connect_index)
    #if this server has been "killed", then dont accept any more connections
    return nil unless @@kill

    connection = @receive_connections[connect_index]
    data = connection.gets
    #if the data triggers a kill, then call the kill function 
    self.kill if (0 == (/kill/ =~ data))
    
    #if the data is a backup, then call the backup function to properly receive it
    self.receive_backup(connect_index) if (0 == (/backup/ =~ data))

    #otherwise, return the data to whatever function asked for it
    return data
  end

  #send_backup: will send the backup data from a process to the given connection
  #after appending a timestamp.
  def send_backup(connection, *proc_data)
    backup_data = "#{Time.now}: #{proc_data}"
    connection.puts "backup "
    connection.puts backup_data
  end

  #receive_backup: will receive a backup from a process and compare it to existing
  #backups. If it is newer, it will replace the older backup and if not, it will
  #keep the old backup
  def receive_backup(connect_index)
    connection = @receive_connection[connect_index]
    time, backup_data = connection.gets.split(": ")
    
    #if this backup is newer, then use it
    if(@backups[connect_index][0] < time) then
        @backups[connect_index][0] = time
        @backups[connect_index][1] = backup_data
    end
    #otherwise, just return true
    return true
  end

  #kill: if the API needs to be killed, this method keeps the API from continuously
  # failing over to new servers
  def kill
    @@kill = false
  end

  #helper functions that must be private
  private
  #ddos_check: will check all the receiving connections to determine if a failover
  # should occur. If nothing is received for @@failover_timeout seconds, then this
  # server has been DDOSed and if possible, should negotiate a failover. Otherwise,
  # start talking to the backup server for that given server
  def ddos_check
    

  #this method will determine if a failover is needed by constantly checking when
  #the last piece of data was received. After @@failover_timeout seconds with no
  #new data and if there is no data waiting on @@receive_connections, then this
  #function will trigger a failover
  def old_ddos_check(timestamp)
    begin
      #wait for preset length of time
      timeout(@failover_timeout) do
        time = 1
        while true 
          puts "#{time}\n"
          sleep 1
          time += 1
        end
        puts "out of timeout loop"
      end
      rescue TimeoutError
        return if timestamp < @@last_data_received
        length = @receive_connection.length -1
        #now make sure that no one has
        0.upto(length) do |i|
           break if data = @@receive_connections[i].gets
        end
        #if there has not been any activity, then begin failover
        if data.nil? then
          puts "\nInitiating Failover\n"
          self.failover
        end
    end
  end

  def get_local_ip
    orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily
    UDPSocket.open do |s|
      s.connect '64.233.187.99', 1
      s.addr.last
    end
  ensure
    Socket.do_not_reverse_lookup = orig
  end
end
