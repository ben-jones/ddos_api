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
  Special Note: This API is far from perfect and needs a number of changes to create
    a more effective implementation. Chief among these concerns is a need for a
    better data structure for connections of all types. I hope to address this in
    future revisions
=end

#I will need to methods from net/http and socket
require 'net/http'
require 'socket'

class DDOS_API  

  #main ddos methods and variables
  public
  
  #use this alias to point to the object on the server that is processing data
  @service_object

  #list of who to failover to and who is dependent upon this server
  @failover_connnects
  @dependents

  #note that this is an array of sockets to receive data. The 0th element is the
  # array of connections, 1st element is the source ip, the 2nd element is the 
  #source port, the 3rd element is the last time data was received, the 4th 
  #element is the connection id, and th 5th element is whether the 
  #connection is dead or alive
  #fixMe-> search and replace for references to time stamp-> changed from 1st to 3rd
  # element
  #rec_sem is a mutex to provide mutual exclusion
  @rec_connects

  #array of sockets to send data->  0th element is array of connections, 1st element
  # is the destination ip, 2nd element is the destination port
  #send_sem is a mutex to provide mutual exclusion
  @send_connects

  #this class variable stores the local ip 
  @local_ip
  @local_port

  #instance variables for threads should they be needed
  @input_threadT
  @accept_threadT
  @backup_threadT

  #failover_timeout: this constant stores the amount of time to wait for new data
  # before failing over-> note that it will take 2 * @failover_timeout seconds from
  # the last input for a connection to be declared dead
  #status_unsure: array of connections that need to be rechecked to see if they are
  # dead. Uses mutual exclusion
  @failover_timeout
  @status_unsure

  #rec_backups is an instance variable to store the array of backups- each element 
  # is an array that has the timestamp of when the backup was made and the backup 
  # data in marshalled form. 
  #send_backups is an array of connections to backup to and when the last backup was
  # sent to them. It is also the list of connections to monitor and failover
  #force_backup is how long to wait in seconds before forcing the service to make a 
  # backup
  #dead_connects is a list of connections that have been marked as dead. Not used in
  # this version of the API, but my vision for the future is to use this list to 
  # add fail-over servers back into the list after they come back online
  #send_back_sem, rec_back_sem, and dead_sem are mutexes to provide mutual exclusion
  @force_backup
  @rec_backups
  @send_backups
  @dead_connects

  #semaphore to lock access to data-> please note that it would not be feasible for
  # me to implement something like priority inheritance, so to avoid priority
  # inversion, these semaphore MUST be waited on in the order that they are listed
  @dead_sem
  @status_sem
  @rec_back_sem
  @send_back_sem  
  @send_sem
  @rec_sem

  #variables to store the current server state

  #kill stores whether the DDOS API has been shut down or not. If it is true, then it
  # has been shut down. If false, then the API should be running
  #alive stores whether this server is under DDOS attack. If alive is true, then it
  # is not under DDOS attack, and if it is false, then it is under DDOS attack
  @@kill
  @alive

  #here are some basic accessor methods
  def get_failover_connection
    @failover_connect
  end
  def get_failover_timeout
    @failover_timeout
  end
  def get_service_object
    @service_object
  end
  
  
  #these functions are the actual meat of the API
  
  #use the constructor to initialize attributes that dont require processing
  def initialize(failover_timeout, local_ip, local_port, service_object)
    #set the failover timeout to failover_timeout
    @failover_timeout = failover_timeout

    #set the incoming connection information
    @local_ip = local_ip
    @local_port = local_port

    #set kill to false so that the API will keep processing IO as long as kill is
    #not already true
    @@kill = false if !@@kill

    #set up the mutexes to provide mutual exclusion
    @send_sem = Mutex.new
    @rec_sem = Mutex.new
    @send_backup_sem = Mutex.new
    @rec_backup_sem = Mutex.new

    #set @service_object up as a reference to the service's object
    @service_object = service_object
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
            return string
        end
      end

      #if the last ip read was the ip and of this server, then select the next port
      #and ip. If this is the end of the file, then rewind to the beginning and use
      #the first connection listed in the text document
      if(ip == @local_ip) then
          line = failover.gets
          if(line == nil)pp then
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

    #now set up a thread to accept new connections
    server = TCPServer.new(@local_ip, @local_port)
    @accept_threadT = Thread.new(server) {|server| accept_thread(server)}
    #and another thread to handle input
    @input_threadT = Thread.new { input_thread()}
    #and another thread for backups
    @backup_threadT = Thread.new { backup_thread()}

    #set/ return the value of the failover connection
    @failover_connects.address, @failover_connects.port = [ip], [port]
  end

  #threading functions: this functions are infinite loops that will also determine
  #when a failover is necessary
  
  #accept_thread: takes in the open TCPServer socket and accepts connections as they
  #come in 
  def accept_thread(server)
    #loop until the API is killed
    while !@@kill do
      new_connect = server.accept()
      sock_info = new_connect.remote_address.ip_unpack
      
      #get a lock on @rec_connects, then add stuff onto it
      @rec_sem.lock
      index = @rec_connects.length

      #append the connection's information onto the end of @rec_connect
      @rec_connects[0] << new_connect
      @rec_connects[1] << sock_info[0]
      @rec_connects[2] << sock_info[1]
      @rec_connects[3] << Time.now
      @rec_connects[4] << @rec_connects.length
      
      #now let another thread use the connections
      @rec_sem.unlock
    end
  end

  #input_thread: checks to be sure that input is still coming in. If there has
  # been no input in @fail_timeout seconds, then initiate a failover. If a
  # specific connections has not had any input in @fail_timeout seconds, then
  # failover that connection
  def input_thread
    #fixMe-> add failover logic and failover_server function for monitored
    # connections
    #loop until the API is killed- note using dc because I don't have any writes or
    # exception streams that I care about
    while !@@kill do
      #this is really inefficient in terms of memory copying, but I need to make sure
      # that @rec_connects is not modified while I wait for IO and I will use
      # input_array many times
      #fixMe-> may need to change how I get input because this will take a
      # comparatively long time and such a long data access will reduce concurrency
      @rec_sem.lock
      input_array = @rec_connects[0] 
      #now let someone else use the connections
      @rec_sem.unlock

      inputs, dc, dc = select(input_array,[],[],@fail_timeout)

      #if there has not been any input in @fail_timeout seconds, then assume that 
      # the local server was DDOSed
      self.failover_all if inputs.nil?

      #now iterate over every connection waiting to give input
      inputs.each do |connection|
        #now find the appropriate index to the connections that have received data
        0..input_array[0].length do |num|
          index = num if connection.equal? input_array[0][num]
        end

        #now get the @rec_connects data back for some writes
        @rec_sem.lock
        #reset the timestamp for this connection to the current time
        @rec_connects[4][index] = Time.now
        #if this connection was marked as dead, now mark it as alive
        @rec_connects[5][index] = true
        #and give @rec_connects back to other processes
        @rec_sem.unlock

        #and finally process this data with receive_data
        self.receive_data(index)
      end

      #now check the failover state for individual connections
      for 0..input_array.length do |num|

        #if a server has not sent anything in failover timeout seconds, then
        # check if the server is alive. If not, then fail it over
        #Note that input_array[5] is true if the connection is alive
        if input_array[5][num] || input_array[3][num] < (Time.now - @fail_timeout) then
          #just to be sure that nothing has changed since this does not account for
          # the last round of IO, ensure that @rec_connects is the same as 
          # input_array for this connection
          @rec_sem.lock
          break if (@rec_connects[3] != input_array[3] || @rec_connects[4] != input_array[4] || @rec_connects[5] != input_array[5])
          #now give the data back
          @rec_sem.unlock
          
          #send a message to the server to check its status
          send_alive(num)
        end
      end
    end
  end
    
  #backup_thread: use this function in a seperate thread to force a backup after
  # force_backup seconds
  def backup_thread
    #this thread does not need to run very often and I want to make sure it is not
    # frequently scheduled. Therefore, I am going to do a join on the input thread
    # until time expires. Note that this join will never return anything other than 
    # nil because the input thread is in an infinite loop and is essentially a wait
    until @input_threadT.join(@force_backup) do
      backups_to_force = []
      #find any backups that are too old
      #acquire data lock
      @send_back_sem.lock
      @send_backups[0].each_index do |index|
        #if the backup is older than @force_backup seconds, then force a backup
        backups_to_force << index if @send_backups[1][index] < (Time.now - @force_backup)
      end
      #release lock on send_backups
      @send_back_sem.unlock
      #force a backup for those that are too old
      data = @service_object.to_yaml
      backups_to_force.each do |backup|
        send_backup(backup, data)
      end
    end
  end

  #we are now done with threading functions so move onto other public methods
  
  #check_status(nil): examine the connections on the status_unsure list and if a
  # server has exceeded the time limit to respond to the send_alive call or the
  # send_alive call returns that the server is dead(designed to make testing easier)
  # then close the connection and delete it. 
  #Note: this server never marks servers as alive. That is done in the input thread
  # and proc_alive
  #fixMe-> refactor to provide more concurrency
  #fixMe-> refactor to contain failover_logic
  def check_status()
    #loop through every element in the status unsure array
    @status_sem.lock
    length = @status_unsure.length
    @status_sem.unlock

    for 0..length do |index|
      #for greater concurrency, unlock and relock the data on each loop
      @status_sem.lock

      #if time is expired, or the status of the connection has been set to dead,
      # then mark the connection as dead
      if @failover_timeout < (@status_unsure[3][index] - Time.now) || @status_unsure[5][index] == false then
        #if the connection is a failover connection and is being monitored, then
        # perform additional logic and initiate failover
        #if the local server is a hot failover for this remote server, then
        # fail it over and inform its dependent servers
        
        #don't need to acquire data because it is already locked
        address , port = @status_unsure[0][index], @status_unsure[2][index]
        id = @status_unsure[4][index]

        #for a more versatile API, this should be changed to accomodate
        # monitoring of more than one server
        #acquire lock on the @send_backups data
        @send_back_sem.lock
        if address == @send_backups[1] && port = @send_backups[2] then
          #release the data
          @send_back_sem.unlock
          
          #tell the failed server that it is being failed over
          #acquire data lock
          @send_sem.lock
          send_index = find_by_ip(address, port, @send_connects)
          #release the data
          @send_sem.unlock
          failover_server(send_id, -1, send_id)

          #and inform all its dependent servers
          @dependents[0].each_index do |dep_index|
            dep_ip, dep_port = @dependents[1][dep_index], @dependents[2][dep_index]
            #either use an existing connection, or open a new one if the local
            # server is not communicating with it
            dep_index = find_by_ip(dep_ip, dep_port)
            if dep_index.nil? then failover_server(send_index, -1, dep_ip, dep_port)
            else failover_server(send_index, -1, dep_index)
            end
          end

          #now set the failover server's status to dead
          mark_dead(id)
        #now for the case that the server is not a backup, just mark it as dead
        else then
          #make sure that data is released
          @send_back_sem.unlock
          
          #now mark the server as dead
          mark_dead(id)
        end
      end
      #unlock the data for greater concurrency before we loop through again
      @status_sem.unlock

    end
  end

  #send_data: this function will send proc_data to the given connection.
  # this is yet another overloaded version of the send_data method. This version will
  # create a new socket from ip_address and port_num
  def send_data(address, port_num, *proc_data)
    connection = TCPSocket.new(address, port_num)
    #acquire lock on data
    @send_sem.lock
    connect_index = @send_connects.length
    @send_connects << connection
    #release lock
    @send_sem.lock
    self.send_data(connect_index, proc_data)
  end
  #this function just looks up the connection info via its connectionIndex and then
  # sends the data
  def send_data(connect_index, *proc_data)
    #if this server has been "killed", then don't send anything
    return nil if @kill

    #I have included some basic error handling here
    begin
      raise ArgumentError, "No argument" if connect_index.nil?
      raise ArgumentError, "Invalid Connection index" if (connect_index < 0 || connect_index > @send_connects.length)
      rescue => err
        puts err
      return connect_index
    end
    
    #now just send the data with a terminating character
    #acquire data lock
    @send_sem.lock
    @send_connects[connect_index].puts proc_data
    @send_connects[connect_index].puts "|::|"
    #release lock
    @send_sem.unlock

    #and finally return connect_index
    return connect_index
  end

  #receive_data: will receive data from a server and pass it to the get_data method
  # of the service object
  def receive_data(index)
    #if this server has been "killed", then dont accept any more connections
    return nil if @@kill
    
    #read in the first 5 characters to determine where to go from here and then 
    # read in the rest of the data up to the next seperator, |:
    #acquire data lock
    @rec_sem.lock
    meth_sel =  @rec_connects[0][index].read(5)
    data = @rec_connects[0][index].gets("|::|")
    #release lock
    @rec_sem.unlock
    #remove white space from meth_sel and the data seperator, |::|, from the data
    meth_sel.rstrip!
    data.chomp!("|::|")

    #use a case statement to determine what method to call
    case meth_sel
    when "kill"
      self.kill
    when "back"
      receive_backup(data)
    when "fail"
      fail_proc(index, data)
    when "alive"
      alive_proc(index, data)
    else
      #otherwise, give the data to the service by handing it to the get_data method

      #get the connection's id # 
      #acquire data lock
      @rec_sem.lock
      id = @rec_connects[4][connect_index]
      #release lock
      @rec_sem.unlock

      #and send the data
      @service_object.get_data(data, int connect_index)
    end

    #fixMe-> add support for failover and check_alive method calls on remote servers
  end

  #send_backup: will send the backup data from the service to the given connection
  # by marshalling the service object using yaml
  def send_backup(id, backup_data)
    #find the connection by using its id
    #acquire data lock
    @send_sem.lock
    connection = find_by_id(id, @send_connects)
    #release lock
    @send_sem.unlock

    #if there is not a sending connection for the id yet, such as if data has only 
    # been received, then create a new connection to send the backup
    if connection.nil? then
      #acquire data lock
      @rec_sem.lock
      connect_to_copy = find_by_id(id, @rec_connects)
      #release data lock
      @rec_sem.unlock

      ip, port = connect_to_copy.remote_server.ip_unpack
      connection = TCPSocket.new(ip, port)
      #now add the connection to @send_connects, but don't add it to @send_backups
      # because we do not know if it could handle failover
      #acquire lock on data
      @send_sem.lock
      @send_connects[0] << connection
      @send_connects[1] << ip
      @send_connects[2] << port
      @send_connects[4] << id
      #release data
      @send_sem.unlock
    end

    #now send the data with a terminating character
    connection.puts "backup "
    connection.puts "#{Time.now}|: "
    connection.puts backup_data
    connection.puts "|::|"
  end
  #send_backup: overloaded version of backup method. If the service wants to back
  # itself up and either wants to backup all of its failover servers or is unaware
  # of who to back itself up to, it should call this method
  def send_backup
    backup_data = @service_object.to_yaml
    @send_backups[0].each_index do |back_index|
      send_backup(back_index, backup_data)
    end
  end
  #send_backup: overloaded version of backup method. If the service wants to back
  # itself up to a certain connection, then it calls this method which marshals it
  # and sends the data to send_backup
  def send_backup(id)
    backup_data = @service_object.to_yaml
    send_backup(id, backup_data)
  end

  #receive_backup: will receive a backup from a process and compare it to existing
  # backups. If it is newer, it will replace the older backup and if not, it will
  # keep the old backup. This function returns 0 for error, 1 if it used this backup,
  # and 2 if it used the old backup
  def receive_backup(backup_data)
    time, backup_data = backup_data.split("|: ")
    
    #if this backup is newer, then use it
    @rec_back_sem.lock
    if(@rec_backups[connect_index][0] < time) then
      @rec_backups[connect_index][0] = time
      @rec_backups[connect_index][1] = backup_data
      @rec_back_sem.unlock
      return 1
    else
      @rec_back_sem.unlock
    end
    
    #otherwise, just return 2 to indicate that the old backup was newer
    return 2
  end

  #failover_all: this function will fail the local server over after it has been 
  # DDOSed. In a realistic scenario, this function would not be able to do anything
  #fixMe-> finish writing
  def failover_all
    #send failover_server notice to all
    @myDependencies
  end

  #failover_server(source_serv, dest_serv, rec_serv): this function will 
  # instruct the recepient server, rec_serv, to begin using dest_serv instead of 
  # source_serv. 
  #fixMe-> a dest_serv of -1 is a reference to self, use ids, not index
  def failover_server(source_serv, dest_serv, rec_serv)
   #fixMe-> finish writing
  end

  #send_alive: will send a check alive message to a remote server to see if it is
  # still alive
  def send_alive(index)
    #fixMe-> finish writing and add functionality to check timestamps for other
    # connections with the same id
    #get the id for the given index
    #acquire data
    @rec_sem.lock
    id = @rec_connects[4][index]
    @rec_sem.unlock

    #now find the connection in send connections
    @send_sem.lock
    connection = find_by_id(id, @send_connects)
    #data will be released after sending if the connection exists

    #if the connection does not exist yet, then create it
    if connection.nil? then
      #release the lock for a few instructions for greater concurrency
      @send_sem.unlock

      #now lock the receive list to get the ip and port info
      @rec_sem.lock
      ip, port = @rec_connects[1][index], @rec_connects[2][index]
      @rec_sem.unlock

      #create the connection
      connection = TCPSocket.new(ip, port)      

      #now add the connection onto the list
      @rec_sem.lock
      @rec_connects[0] << connection
      @rec_connects[1] << ip
      @rec_connects[2] << port
      @rec_connects[3] << Time.now
      @rec_connects[4] << id
      @rec_sem.unlock
    end

    #create a message to send to the other server
    data_to_send = "alive send #{@local_ip} #{@local_port}"
    #finally, send a simple alive command back
    send_data(index, data_to_send)
  end
  
  #proc_alive: will process an incoming check_alive request and adjust accordingly
  # the data structures to reflect the receipt of new input
  def proc_alive(id, data)
    #fixMe-> finish writing and switch some functionality to check_alive

    #set the value of alive 
    alive = true if !@@kill && @alive
    else alive = false

    #split the data into a selector, hostname, and port based on a space 
    selector, ip, port, rest = data.split(" ")
    
    #determine whether we are sending our status or receiving info about another
    # servers status
    case selector
    when "send"
      if(alive) then
        data_to_send = "alive ret #{ip} #{port} #{alive}"
        #see if there is already a connection and pick send_data method accordingly
        @send_sem.lock
        connection = find_by_ip(ip, port, @send_connects)
        @send_sem.unlock
        #if there is not a connection already, have send_data create one
        if connection.nil? then send_data(ip, port, data_to_send)
        else then send_data(connection, data_to_send)
        end
      end
    when "ret"
      #begin by setting the status of all these connections to alive
      #find the id
      @send_sem.lock
      index = find_by_ip(ip, port, @rec_connects)
      id = @rec_connects[4][index]
      connects = find_all_by_id(id, @rec_connects)
      #and update these connections
      for connects.each do |index|
        @rec_connects[3][index] = Time.now
        @rec_connects[5][index] = true
      end
      @send_sem.unlock

      #now move onto @status_unsure
      @status_sem.lock
      for @status_unsure.each_index do |index|
        #if the id is the same, then remove it from @status_unsure
        if @status_unsure[4] == id then
          @status_unsure[0].delete_at(index)
          @status_unsure[1].delete_at(index)
          @status_unsure[2].delete_at(index)
          @status_unsure[3].delete_at(index)
          @status_unsure[4].delete_at(index)
          @status_unsure[5].delete_at(index)
        end
      end
      @status_sem.unlock
    end
  end

  #proc_fail: will process an incoming failover request and determine what actions 
  # to take
  #fixMe-> finish writing
  def proc_fail(request)
  end

  #kill: if the API needs to be killed, this method keeps the API from continuously
  # failing over to new servers
  #Note: this is a class instance variable
  def kill
    @@kill = true
  end

  def unkill
    @@kill = false
  end

  #helper functions that must be private
  private

  #mark_dead(int id): will mark all connections with the given id as dead and close
  # the connections. Though this implementation won't use it, I am also adding the
  # connection info to a list of dead connections. 
  #Note: this method is designed to be called for connections that are already on the
  # @status_unsure list
  #fixMe-> finish writing and deal with dependent servers
  def mark_dead(id)
    #start by getting the connection's info from status unsure or rec_connects
    @status_sem.lock
    index = find_by_id(id, @status_unsure)
    ip, port = @status_unsure[1][index], @status_unsure[2][index]
    @status_sem.unlock

    #add the connection to the @dead_connects list using the standard notation even
    # though the 0th element in dead_connects will be nil because there is not an
    # associated connection
    @dead_sem.lock
    @dead_connects[1][index] << ip
    @dead_connects[2][index] << port
    @dead_connects[3][index] << Time.now
    @dead_connects[0][index] << id
    @dead_sem.unlock

    #get and mark as dead all receiving connections with the given id
    @rec_sem.lock
    connects = find_all_by_id(id)
    #now mark each connection as dead and close it
    for connects.each_index do |index|
      #close the connection
      connects[0][index].close
      #set status field to dead
      connects[5][index] = false
      #I am leaving the ip, port, and time stamp fields unchanged
    end
    @rec_sem.unlock

    #now do the same for the sending connections
    @send_sem.lock
    connects = find_all_by_id(id)
    #now mark each connection as dead and close it
    for connects.each_index do |index|
      #close the connection
      connects[0][index].close
      #set status field to dead
      connects[5][index] = false
      #I am leaving the ip, port, and time stamp fields unchanged
    end
    @send_sem.unlock
  end

  #change_serv: will close the connection to source_serv and replace its entries in
  # rec_connects and send_connects with dest_serv. If there is not an open connection
  # to dest_serv, it will open it before replacing the references
  #fixMe-> finish writing
  def change_serv(source_serv, dest_serv)
  end

  #find_by_ip: will find the connection to the socket given by address and port in
  # the connection list given by list. If it is not found, the method will return nil
  #fixMe-> add mutual exclusion
  def find_by_ip(address, port, list)
    list.each_index do |index|
      return index if ip == list[1][index] && port == list[2][index]
    end
    #if the address hasn't been found, return nil
    return nil
  end

  #find_by_id: will find the connection to the socket given by address and port in
  # the connection list given by list. If it is not found, the method will return nil
  #fixMe-> add mutual exclusion
  def find_by_id(id, list)
    list[4].each_index do |index|
      return index if list[4][index] == id
    end
  end
    
  #find_all_by_id(int id, reference * list): will return all connections in the given
  # list with the given id
  def find_all_by_id(id, list)
    connects = []
    list[4].each_index do |index|
      if list[4][index] == id then
        connects << index
      end
    end
  end

end
