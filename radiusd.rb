#!/usr/bin/env ruby
require 'rubygems'
require 'eventmachine'
require 'lib/packet'
 
class RadiusServer < EM::Connection
 
 def receive_data(data)
	dict = Radius::Dict.new
	File.open("./dictionary") do | fn | dict.read(fn) end
 	radiusPacket = Radius::Packet.new(dict)
	radiusPacket.unpack(data)
  puts	radiusPacket.to_s("")
 end
end
 
 
EM.run do
 host = '0.0.0.0'
 port = 1813
 EM.epoll
 EM.open_datagram_socket host, port, RadiusServer do | connection |
end
end
