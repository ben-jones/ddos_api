#Ben Jones
#Spring 2012
#other_server.rb: this script will act like another server and allow me to debug
# some functions
require 'socket'

puts "\nStarting acceptance server\n"
listen = TCPServer.new('localhost', 5000)

connect = listen.accept

#now wait until we get a connection or input
while true do
  data, dc, dc = select([connect], nil, nil, 5)
  if !data.nil? then
    puts data[0].gets("|::|")
    puts "Data has been put on the screen\n"
  end
end
