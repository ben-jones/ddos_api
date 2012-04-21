#Ben Jones
#Spring 2012
#other_server.rb: this script will act like another server and allow me to debug
# some functions
require 'socket'

puts "\nStarting acceptance server\n"
listen = TCPServer.new('localhost', 5000)

connect = listen.accept

send_sock = TCPSocket.new('localhost', 6000)


#now wait until we get a connection or input
while true do
  data = gets
  if !data.nil? then
    "sending data #{data}"
    send_sock.puts data
    send_sock.puts "|::|"
    puts "Data has been sent\n"
  end
end
