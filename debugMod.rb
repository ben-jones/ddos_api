#Module Debug: this module includes a bunch of printing statements and status methods
# that will allow the user to see much more clearly what is happening in the function
module Debug

  #include a bunch of getter and setter methods to make life easier


  #here are some status methods -> will return the status of this instance of the API

  #still_alive(nil): will return true if this server is still alive, false otherwise
  def still_alive
    if @@kill == false and @alive == true then
      return true
    else
      return false
    end
  end

  #check_connect_alive(string ip, int port): will check if the connection referenced
  # with ip and port is still alive in the connections list
  def check_connect_alive(ip, port)
     if find_index_by_ip(ip, port, @connects).nil? then
       return false
     else
       return true
     end
  end

end
