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
require 'socket.rb'

class DDOS_API  

  #main ddos methods and variables
  public
  
  #use this alias to point to the object on the server that is processing data
  @service_object

  #list of who to failover to and who is dependent upon this server
  #fail_to: list of who we could failover to
  #fail_rec: list of backups and who we are monitoring in case we need to
  # failover
  #dependents: list of who is dependent upon the local server
  #fail_back_mode: set to true to indicate we are just a hot failover, and false to
  # indicate that we are not a hot failover
  #these lists use the fail_to_sem, fail_rec_sem, and dep_sem mutexes for mutual
  # exclusion
  @fail_to
  @fail_rec
  @dependents
  @fail_back_mode


  #note that this is an array of sockets. The 0th element is the
  # array of connections, 1st element is the source ip, the 2nd element is the 
  # source port, the 3rd element is the last time data was received, the 4th 
  # element is the connection id, and th 5th element is whether the 
  # connection is dead or alive
  #conn_sem is a mutex to provide mutual exclusion
  @connects

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
  #force_backup is how long to wait in seconds before forcing the service to make a 
  # backup to the fail_to connections list
  #dead_connects is a list of connections that have been marked as dead. Not used in
  # this version of the API, but my vision for the future is to use this list to 
  # add fail-over servers back into the list after they come back online
  #send_back_sem, rec_back_sem, and dead_sem are mutexes to provide mutual exclusion
  @force_backup
  @rec_backups
  @dead_connects

  #associative arrays to store ip to id and id to ip conversions
  #to_id_table: associative array to turn ip and port numbers into id numbers
  #maxId: this is a counter to store the highest id used so far. id_sem must be
  # acquired before this variable can be accessed
  #to_ip_table: hash table to turn id numbers into ip and port combinations
  #ip_sem and id_sem are mutexes for mutual exclusion
  @to_id_table
  @to_ip_table
  @maxId

  #semaphore to lock access to data-> please note that it would not be feasible for
  # me to implement something like priority inheritance, so to avoid priority
  # inversion, these semaphores MUST be waited on in the order that they are listed
  @dead_sem
  @dep_sem
  @ip_sem
  @id_sem
  @status_sem
  @rec_back_sem
  @fail_rec_sem
  @fail_to_sem  
  @conn_sem


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

    #set kill to false so that the API will keep processing IO as long as @@kill is
    # not already false or it is not already defined
    if defined?(@@kill).nil? or !@@kill then
      @@kill = false
    end

    #set up the mutexes to provide mutual exclusion
    @conn_sem = Mutex.new
    @send_backup_sem = Mutex.new
    @rec_backup_sem = Mutex.new
    @dead_sem  = Mutex.new
    @dep_sem = Mutex.new
    @status_sem = Mutex.new
    @ip_sem = Mutex.new
    @id_sem = Mutex.new

    #set @service_object up as a reference to the service's object and make sure
    # that it can handle the to_yaml, and get_data methods
    begin
      if !service_object.respond_to?("to_yaml", true) or !service_object.respond_to?("get_data", true) then
         raise
      end
    rescue
      puts "\nService Object lacks needed methods. Must define and implement\n"
      puts "both a get_data and to_yaml method as outlined in the documentation"
    end
    @service_object = service_object
  end

  #config_api: will read in the ip address of the next server to failover to and
  # store the socket in failover_connect
  #Note: this method should be called before using the rest of the API
  #fixMe-> update for new API setup
  def config_api(failover_filename="failover.txt")
    #then read in the failover data from a file
    failover = File.open(failover_filename,"r")

    #use a flag to see if the failover ip is set inside this loop
    failover_socket_set = false

    #now iterate over each line and find the next failover ip and port from the file
    while line = failover.gets do
      #remove the trailing new line character
      line.chomp!

      #split the info into local connection and failover connection info
      local_info, rest_info = line.split("fail_rec")
      #remove whitespace
      local_info.rstrip!
      rest_info.lstrip!
      #read in the local connection info
      local_ip, local_port = local_info.split(" ")
      @local_ip, @local_port = local_ip, local_port.to_i

      #now separate it into fail_to and fail_rec servers and then into port and ip
      # info before adding it all to the respective lists
      fail_rec, fail_to = rest_info.split("fail_to")
      fail_rec.rstrip
      fail_to.strip
      #split the string on each of the spaces to get out the ports and ips
      fail_rec_array = fail_rec.split(" ")
      #now read in the fail_rec data
      fail_index = 0
      array_index = 0
      while index =< (fail_rec_array.length/ 2) do
        @id_sem.lock
        @fail_rec_sem.lock

        #get the ip and port from the input
        ip = fail_rec_array[array_index]
        port = fail_rec_array[array_index + 1].to_i
        array_index += 2

        #create the id-> this is why we had to lock the @to_id table
        id = get_id_by_ip(ip, port)
        
        #add the connection information and wait for the input thread to add in the
        # connection info since the server sending the failover will initiate all
        # communication
        @fail_rec[0][fail_index] = nil
        @fail_rec[1][fail_index] = ip
        @fail_rec[2][fail_index] = port
        @fail_rec[3][fail_index] = id
        @fail_rec[4][fail_index] = Time.now
        @fail_rec[5][fail_index] = true



        #now set up the fail recepients connections

        #here the local server will create a connection to the fail recepient
        @fail_to[0][fail_index] = TCPSocket.new(ip, port)
      


      #if the last ip read was the ip and of this server, then select the next port
      # and ip. If this is the end of the file, then rewind to the beginning and use
      # the first connection listed in the text document
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

    #now set up a thread to accept new connections
    server = TCPServer.new(@local_ip, @local_port)
    @accept_threadT = Thread.new(server) {|server| accept_thread(server)}
    #and another thread to handle input
    @input_threadT = Thread.new { input_thread()}
    #and another thread for backups
    @backup_threadT = Thread.new { backup_thread()}

    #set/ return the value of the failover connection
    @failover_connects.address, @failover_connects.port = ip, port
  end

  #threading functions: this functions are infinite loops that will also determine
  # when a failover is necessary
  
  #accept_thread: takes in the open TCPServer socket and accepts connections as they
  # come in 
  def accept_thread(server)
    #loop until the API is killed
    while !@@kill do
      new_connect = server.accept()
      ip, port = new_connect.remote_address.ip_unpack
      
      #find out if there is already another connection, sending or receiving, with
      # this id and if so, then set that to the id
      @id_sem.lock
      assoc_index = "#{ip} #{port}"
      id = @to_id_table[assoc_index]
      #if there is not already an entry, then add the info into the table
      if id.nil? then
        id = @maxId
        @to_id_table[assoc_index] = id
        @maxId += 1
      end
      @id_sem.unlock
      
      #get a lock on @connects, then add stuff onto it
      @conn_sem.lock
      index = @connects.length

      #append the connection's information onto the end of @connects
      @connects[0][index] = new_connect
      @connects[1][index] =  ip
      @connects[2][index] =  port
      @connects[3][index] =  Time.now
      @connects[4][index] = @connects.length
      @connects[5][index] = true
      
      #now let another thread use the connections
      @conn_sem.unlock
    end
  end

  #input_thread: checks to be sure that input is still coming in. If there has
  # been no input in @fail_timeout seconds, then initiate a failover. If a
  # specific connections has not had any input in @fail_timeout seconds, then
  # failover that connection
  def input_thread
    #fixMe-> add failover logic and send_fail function for monitored
    # connections
    #fixMe-> use loop instead of select to ensure that I am properly locking the
    # data and not creating problems

    #set up a timestamp to tell if we have been DDOSed
    overall_timestamp =  Time.now

    #loop until the API is killed- note using dc because I don't have any writes or
    # exception streams that I care about
    while !@@kill do
      #this is really inefficient in terms of memory copying, but I need to make sure
      # that @connects is not modified while I wait for IO and I will use
      # input_array many times
      #fixMe-> may need to change how I get input because this will take a
      # comparatively long time and such a long data access will reduce concurrency

      #now get the length of the connection array
      @conn_sem.lock
      length = @connects.length
      @conn_sem.unlock
      #now let someone else use the connections
      
      #now loop through every connection in the connection array and see if there
      # is any data to be received and if so, send the data to receive_data
      #Note: I am not just waiting on all the input because I want to ensure mutual
      # exclusion for the connections and I don't want other operations to have to
      # wait forever
      for index in 0...length do
        #acquire a lock on the connection
        @conn_sem.lock
        
        #see if there is any input waiting and if so, then send it to receive_data
        input, dc, dc = select(@connects[0][index],[],[], 0)
        
        #call receive_data if there is data waiting
        if !input.nil? then
          #reset the overall timestamp if data was received
          overall_timestamp =  Time.now
          #and the timestamp for just this connection
          @connects[3][index] = Time.now
          #if this connection was marked as dead, now mark it as alive
          @connects[5][index] = true

          #now receive the data and leave the connections unlocked until the next
          # loop
          @conn_sem.unlock
          receive_data(index)
        else
          #if a server has not sent anything in failover timeout seconds, then
          # check if the server is alive. If not, then send it a message and
          # mark it for followup
          #Note that input_array[5] is true if the connection is alive
          if input_array[5][index] && input_array[3][index] < (Time.now - @fail_timeout) then
            #send a message to the server to check its status
            send_alive(index)
          end
          #release the data to increase concurrency
          @conn_sem.unlock
        end
      end
        
      #now that we have gotten all the waiting input, see if any failover actions
      # need to be taken and check up on those connections on the status_unsure list
      check_status

      #if there has not been any input in @fail_timeout seconds, then assume that 
      # the local server was DDOSed
      @conn_sem.unlock
      self.self_fail if (Time.now - overall_timestamp) > @fail_timeout
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
        backups_to_force << index if @send_backups[3][index] < (Time.now - @force_backup)
      end
      #release lock on send_backups
      @send_back_sem.unlock
      #force a backup for those that are too old
      data = @service_object.to_yaml
      backups_to_force.each do |backup|
        #acquire data
        @send_back_sem.lock
        #get the id and update the time stamp
        id = @send_backups[4][backup]
        @send_backups[3][backup] = Time.now
        #release data
        @send_back_sem.unlock

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

    for index in 0..length do
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
          @conn_sem.lock
          send_index = find_by_ip(address, port, @connects)
          send_id = @connects[4][send_index]
          #release the data
          @conn_sem.unlock
          send_fail(send_id, -1, send_id)

          #and inform all its dependent servers
          @dependents[0].each_index do |dep_index|
            dep_ip, dep_port = @dependents[1][dep_index], @dependents[2][dep_index]
            #either use an existing connection, or open a new one if the local
            # server is not communicating with it
            dep_index = find_by_ip(dep_ip, dep_port)
            if dep_index.nil? then send_fail(send_id, -1, dep_ip, dep_port)
            else send_fail(send_id, -1, dep_index)
            end
          end

          #now set the failover server's status to dead
          mark_dead(id)
        #now for the case that the server is not a backup, just mark it as dead
        else
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
    @conn_sem.lock
    connect_index = @conn_connects.length
    @conn_connects << connection
    #release lock
    @conn_sem.lock
    send_data(connect_index, proc_data)
  end
  #this function just looks up the connection info via its connectionIndex and then
  # sends the data
  def send_data(connect_id, proc_data)
    #if this server has been "killed", then don't send anything
    return nil if @kill
    
    #now find the ip and port from the id
    @ip_sem.lock
    ip, port = @to_ip_table[connect_id].split(" ")
    @ip_sem.unlock
    #now just send the data with a terminating character
    #acquire data lock
    @conn_sem.lock
    @connects[connect_index].puts proc_data
    @connects[connect_index].puts "|::|"
    #release lock
    @conn_sem.unlock

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
    @conn_sem.lock
    meth_sel =  @connects[0][index].read(5)
    data = @connects[0][index].gets("|::|")
    #release lock
    @conn_sem.unlock
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
      proc_fail(index, data)
    when "alive"
      proc_alive(index, data)
    else
      #otherwise, give the data to the service by handing it to the get_data method
      @service_object.get_data(data, index)
    end

    #fixMe-> add support for failover and check_alive method calls on remote servers
  end

  #send_backup: will send the backup data from the service to the given connection
  # by marshalling the service object using yaml
  def send_backup(id, backup_data)
    #find the connection by using its id
    #acquire data lock
    @conn_sem.lock
    connection = find_by_id(id, @connects)
    #release lock
    @conn_sem.unlock
    
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
      @send_back_sem.lock
      send_backup(back_index, backup_data)
      @send_back_sem.unlock
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
    if(@rec_backups[connect_index][3] < time) then
      @rec_backups[connect_index][3] = time
      @rec_backups[connect_index][0] = backup_data
      @rec_back_sem.unlock
      return 1
    else
      @rec_back_sem.unlock
    end
    
    #otherwise, just return 2 to indicate that the old backup was newer
    return 2
  end

  #self_fail(nil): this function will fail the local server over after it has been 
  # DDOSed. In a realistic scenario, this function would not be able to do anything
  #fixMe-> finish writing
  def self_fail
    #tell the failover server that it will be receiving data
    #acquire data lock
    @conn_sem.lock
    send_index = find_by_ip(@failover_connects[1], @failover_connects[2], @connects)
    send_id = @connects[4][send_index]
    #release the data
    @conn_sem.unlock
    send_fail(-1, send_id, send_id)
    
    #and inform all our dependent servers
    @dep_sem.lock
    @dependents[0].each_index do |dep_index|
      dep_ip, dep_port = @dependents[1][dep_index], @dependents[2][dep_index]

      #either use an existing connection, or open a new one if the local
      # server is not communicating with it
      dep_index = find_by_ip(dep_ip, dep_port)
      dep_index = create_connect(dep_ip, dep_port) if dep_index.nil?
      send_fail(-1, send_id, dep_index)
    end
    @dep_sem.unlock

    #now set our status to dead
    @alive = false
  end

  #send_fail(fail_from, fail_to, rec_serv): this function will instruct the 
  # recepient server, dest_serv, to begin using fail_to instead of fail_to.
  #Note: a reference of -1 is a reference to self, use ids, not index
  def send_fail(fail_from, fail_to, rec_serv)
    #if fail_from is set to -1, then it is a reference to the local server and use
    # that data
    if(fail_from == -1) then
      fail_from_ip, fail_from_port = @local_ip, @local_port      
    else
      #acquire data and find the data from the receiving connection
      @conn_sem.lock
      fail_from_index = find_by_id(fail_from, @connects)
      fail_from_ip = @connects[1][fail_from_index]
      fail_from_port = @connects[2][fail_from_index]
      @conn_sem.unlock
    end
    
    #now find the data for the destination of the failover from fail_to and if it is
    # set to -1, then use the local server's info
    if(fail_to == -1) then
      fail_to_ip, fail_to_port = @local_ip, @local_port      
    else
      #acquire data and find the data from the receiving connection
      @conn_sem.lock
      fail_to_index = find_by_id(fail_to, @connects)
      fail_to_ip = @connects[1][fail_to_index]
      fail_to_port = @connects[2][fail_to_index]
      @conn_sem.unlock
    end
    
    #now find the connection to send the message to-> note that we are not checking
    # the case that rec_serv is -1 because it would not make sense to send this to
    # ourselves and any cases that require it would be better left to create a new
    # function for the data manipulation
    @conn_sem.lock
    dest_connect = find_by_id(dest_serv, @connects)
    @conn_sem.unlock
   
    #create the data to send
    data_to_send = "fail #{fail_from_ip} #{fail_from_port} #{fail_to_ip} #{fail_to_port}"
    #and send the data-> be sure to create a connection if a connection does not
    # already exist
    if dest_connect.nil? then
      #find the ip and port to send the data to
      @conn_sem.lock
      index = find_by_id(dest_serv, @connects)
      ip, port = @connects[1][index], @connects[2][index]
      @conn_sem.unlock
      send_data(ip, port, data_to_send)
    else
      send_data(dest_connect, data_to_send)
    end
  end

  #proc_fail(int index, string request): will process an incoming failover request 
  # and determine what actions to take. Note that the API and this function do not
  # care if we are relient upon this server-> if a server that we are dependent upon
  # is being failed over, then we will adjust. 
  # This method will return 1 if it was successful in removing the connection and
  # return 0 if the connection did not exist or there was an error
  def proc_fail(request)
    #start by parsing the ip and port info from the data
    fail_from_ip, fail_from_port, fail_to_ip, fail_to_port = request.split(" ")
    
    #check if this request has already been processed. If the server is in dead
    # connects(it was a hot failover or we are dependent upon it) or it is not in
    # connects(closed and killed connection), then return
    @dead_sem.lock
    index = find_by_ip(fail_from_ip, fail_from_port, @dead_connects)
    @dead_sem.unlock
    #return if the index is not nil, aka it was in dead connects
    return 0 if !index.nil?
    
    #now check connects
    @conn_sem.lock
    index = find_by_ip(fail_from_ip, fail_from_port, @connects)
    @conn_sem.unlock
    #if the index is nil, aka the connection is not in connects, then return
    return 0 if index.nil?

    #now find out if we are sending backups to the server, aka are the server's hot
    # failover for each other so that we can use this data later
    @back_sem.lock
    back_index = find_by_ip(fail_from_ip, fail_from_port, @send_backups)
    @back_sem.unlock

    #if the fail_from ip and port are the same as the local server, then initiate a
    # self_fail because the local server has been ddosed
    if(fail_from_ip == @local_ip && fail_from_port == @local_port)
      self_fail

    #if the fail_to ip and port are the same as the local server, then notify all
    # dependents because the local server is taking over-> I am assuming that this
    # is only called when the local server is actually set up as a hot failover for
    # the server
    elsif !back_index.nil?
      #close and delete the connection, but save the id
      @conn_sem.lock
      id = @connects[4][index]
      @connects[0][index].close
      delete_elem(index, @connects)
      @conn_sem.unlock
      
      #now delete the appropriate backup connection and add the connection to
      # the dead connection list
      @send_back_sem.lock
      @send_backups[0][back_index].close
      delete_elem(back_index, @send_backups)
      @send_back_sem.unlock

      #if the local server is specified as the server to failover to, then add the
      # fail_from server to the dead connects list
      @dead_sem.lock;
      dead_index = @dead_connects.length
      @dead_connects[0][dead_index] = nil 
      @dead_connects[1][dead_index] = fail_from_ip
      @dead_connects[2][dead_index] = fail_from_port 
      @dead_connects[3][dead_index] = Time.now
      @dead_connects[4][dead_index] = id
      @dead_connects[5][dead_index] = false
    
    #if this server is not a hot failover, then close the old connection
    # and copy the new connection info into the old slot. Also, if there is an open
    # connection, then replace all entries in check_status and connects with the id
    # of the failed process-> basically, assuming that server will only send data or
    # be a backup, not both because the old id will be erased. I will make this
    # better in future implementations
    else
      #close the old connection, but store the value of the id and update the server
      # referenced by fail_to with this new id-> will update status_unsure and 
      # receive backups along with connects, so I will have to acquire the locks 
      # here to be sure that all data is up to date when the lists are accessed
      
      #now close the connection and delete its data
      mark_dead(@fail_from_ip, @fail_from_port)

      @status_sem.lock
      @rec_back_sem.lock
      @conn_sem.lock
      #close and delete the old connection, but save the id
      new_id = @connects[4][index]
      new_index = find_by_ip(@fail_from_ip, @fail_from_port, @connects)
      @connects[4][new_index] = new_id

      #update the id of the failover connection in connects
      new_index = find_by_ip(@fail_from_ip, @fail_from_port, @connects)
      @connects[4][new_index] = new_id
      @conn_sem.unlock
     
      #update the rec_backups
      new_index = find_by_ip(@fail_from_ip, @fail_from_port, @rec_backups)
      @rec_backups[4][new_index] = new_id
      @rec_back_sem.unlock

      #update the status_unsure list
      new_index = find_by_ip(@fail_from_ip, @fail_from_port, @status_unsure)
      @status_unsure[4][new_index] = new_id
      @status_sem.unlock
    end
  end


  #send_alive: will send a check alive message to a remote server to see if it is
  # still alive
  def send_alive(index)
    #get the id for the given index
    #acquire data
    @conn_sem.lock
    connection = @connects[0][index]
    ip  = @connects[1][index]
    port = @connects[2][index]
    id = @connects[4][index]
    @conn_sem.unlock

    #now add the connection to the status unsure list if it is not already on it
    @status_sem.lock
    on_list = find_by_id(id, @status_unsure)
    #if the connection is not already on the list, then add it
    if on_list.nil? then
      stat_index = @status_unsure[0].length
      @status_unsure[0][stat_index] = connection
      @status_unsure[1][stat_index] = ip
      @status_unsure[2][stat_index] = port
      @status_unsure[3][stat_index] = Time.now
      @status_unsure[4][stat_index] = id
      @status_unsure[5][stat_index] = true      
    end
    @status_sem.unlock

    #create a message to send to the other server
    data_to_send = "alive send #{@local_ip} #{@local_port}"
    #finally, send a simple alive command
    send_data(index, data_to_send)
  end
  
  #proc_alive: will process an incoming check_alive request and adjust accordingly
  # the data structures to reflect the receipt of new input
  def proc_alive(id, data)
    #set the value of alive 
    if !@@kill && @alive then
      alive = true
    else
      alive = false
    end

    #split the data into a selector, hostname, and port based on a space 
    selector, ip, port, rest = data.split(" ")
    
    #determine whether we are sending our status or receiving info about another
    # servers status
    case selector
    when "send"
      if(alive) then
        data_to_send = "alive ret #{ip} #{port} #{alive}"
        #see if there is already a connection and pick send_data method accordingly
        @conn_sem.lock
        connection = find_by_ip(ip, port, @connects)
        @conn_sem.unlock
        #if there is not a connection already, have send_data create one
        if connection.nil? then send_data(ip, port, data_to_send)
        else send_data(connection, data_to_send)
        end
      end
    when "ret"
      #begin by setting the status of all these connections to alive
      #find the id
      @conn_sem.lock
      index = find_by_ip(ip, port, @connects)
      id = @connects[4][index]
      connects = find_all_by_id(id, @connects)
      #and update these connections
      connects.each do |index|
        @connects[3][index] = Time.now
        @connects[5][index] = true
      end
      @conn_sem.unlock

      #now move onto removing connections from @status_unsure
      @status_sem.lock
      @status_unsure.each_index do |index|
        #if the id is the same, then remove it from @status_unsure
        delete_elem(index, @status_unsure) if @status_unsure[4][index] == id
      end
      @status_sem.unlock
    #print an error when there is an unexpected case
    else
      puts "\nError in proc_alive: Invalid processing option\n"
    end
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
  
  #create_connect(string address, int port): this function will create a new
  # connection on the @connects list and return its index
  #Note: this function acquires a lock on the conn_sem and id_sem mutexes and this 
  # must be factored into the order in which you acquire locks
  def create_connect(address, port, id)
    @id_sem.lock
    @conn_sem.lock
    index = @connects.length
    @connects[0][index] = Socket.new(address, port)
    @connects[1][index] = address
    @connects[2][index] = port
    @connects[3][index] = Time.now
    @maxId = @maxId + 1
    @connects[4][index] = @maxId
    @connects[5][index] = true
  end

  #mark_dead(string ip, int port): will mark all connections with the given 
  # id as dead and close the connections. Though this implementation won't use it, 
  # I am also adding the connection info to a list of dead connections. 
  #Note: this method will delete connections on the @connects, @dependents,
  # @status_unsure, and @send_backups
  #fixMe-> finish writing and deal with dependent servers-> concurrently lock all
  # the lists or just dont care that they will not all be synchronized? Is
  # synchronization worth the performance increase
  def mark_dead(ip, port)
    #start by getting the connection's info from @connects
    @conn_sem.lock
    index = find_by_id(id, @connects)
    ip, port = @connects[1][index], @connects[2][index]
    @conn_sem.unlock

    #get and delete all connections with the given ip
    @conn_sem.lock
    connects = find_all_by_ip(ip, port, @connects)
    #now close and delete each connection in the @connects list
    connects.each_index do |index|
      #close the connection
      @connects[0][index].close
      #and delete it
      delete_elem(index, @connects)
    end
    @conn_sem.unlock

    #now do the same list of connections dependent upon us
    @dep_sem.lock
    connects = find_all_by_ip(ip, port, @dependents)
    #now delete and close each connection
    connects.each_index do |index|
      #delete all the data
      delete_elem(index, @dependents)
    end
    @dep_sem.unlock

    #delete the connection data from the send and receive backups list
    # if the list is on the send backups list, and is therefore a failover, then
    # add it to the dead connects list
    @dead_sem.lock
    @send_back_sem.lock
    indices = find_all_by_ip(ip, port, @send_backups)
    indices.each do |index|
      #remove the backup
      delete_elem(index, @send_backups)
    end
    @send_back_sem.unlock
    #if the connection was on the @send_backups list, then add it to the dead list
    # because it is one of our failovers
    if !indices.empty? then
      #add the connection to the @dead_connects list using the standard notation even
      # though the 0th element in dead_connects will be nil because there is not an
      # associated connection
      dead_index = @dead_connects.length 
      @dead_connects[0][dead_index] = nil
      @dead_connects[1][dead_index] = ip
      @dead_connects[2][dead_index] = port
      @dead_connects[3][dead_index] = Time.now
      @dead_connects[4][dead_index] = id
      @dead_connects[5][dead_index] = false
    end
    @dead_sem.unlock

    #find connections to remove on @status_unsure
    @status_sem.lock
    indices = find_all_by_ip(ip, port, @status_unsure)
    indices.each do |index|
      delete_elem(index, @status_unsure)
    end
  end
  
  #delete_elem(int index, reference * list): will delete the connection with the
  # given index on the list. This function will not close the connection however.
  # Will return 0 for failure, 1 for success.
  def delete_elem(index, list)
      #delete all the data
      list[0].delete_at(index)
      list[1].delete_at(index)
      list[2].delete_at(index)
      list[3].delete_at(index)
      list[4].delete_at(index)
      list[5].delete_at(index)
  end


  #change_serv: will close the connection to source_serv and replace its entries in
  # connects with dest_serv. If there is not an open connection
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

  #find_all_by_ip(string address, int port, reference * list): will find all 
  # connections that match the given address and port and return their indices in an
  # array.
  def find_all_by_ip(address, port, list)
    index_array = []
    list.each_index do |index|
      index_array << index if ip == list[1][index] && port == list[2][index]
    end
  end


  #find_by_id: will find the connection to the socket given by address and port in
  # the connection list given by list. If it is not found, the method will return nil
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
  
  #get_id_by_ip(string ip, int port): this method will lookup the id to return to
  # the service based upon the ip-> just have all ips that are failovers for each
  # other return the same id-> use an associative array
  def get_id_by_ip(ip, port)
    #now combine the ip and port into one string
    assoc_index = "#{ip} #{port}"
    id = @to_id_table[assoc_index]
    #if there is not already an entry, then add the info into the table
    if id.nil? then
      id = @maxId
      @to_id_table[assoc_index] = id
      @maxId += 1
    end
    
    #and return it
    return id
  end
end




class Connection
  attr_accessor :id, :cur_connect, :failovers, :backups

  #fail_index-> index of the next server to failover to in the @failover array
  @fail_index
 
  #back_index-> index of the next server to backup-> lets me basically make an
  # iterator(don't have time to work out how to make this of type iterator-> will
  # have to be future improvement)
  @back_index

  #sem-> semaphore to lock access to this connection
  @sem

  #define a bunch of methods to make accessing parts of the variable easier when I
  # rewrite the connection stuff
  def ip
    @cur_connect[1]
  end

  def port
    @cur_connect[2]
  end

  def last_rec
    @cur_connect[3]
  end

  def connect
    @cur_connect[0]
  end

  def next_fail
    failover = @failovers[fail_index]
    fail_index += 1
    failover
  end

  def backup_last_sent=(timestamp)
    @backups[3] = timestamp
  end

  def backups_last_sent
    @backups[3]
  end


  #initialize-> function to create a new connection
  #fixMe-> finish writing

  #fixMe-> this set up with extra logic won't work-> leave this for a possible
  # refactor
  #method to actually perform the failover on the function-> just close connection
  # and move onto next connection in @failovers
  def failover
    fail_from = @failover
  end
end
