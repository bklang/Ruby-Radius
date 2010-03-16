#!/usr/bin/env ruby
require 'rubygems'
require 'eventmachine'
require 'lib/packet'
require 'lib/dictionary'
 
class RadiusServer < EM::Connection
 
 def receive_data(data)
	dict = Radius::Dictionary.new
  dictionary_path="./dictionaries"

  Dir::foreach dictionary_path do |entry|
   if entry!="." && entry!=".."
     dict.load(dictionary_path+"/"+entry)
     end
  end
  
 	radiusPacket = Radius::Packet.new(dict)
	radiusPacket.unpack(data)
  puts	radiusPacket.to_s()+"\n\n"
  send_data radiusPacket.get_accounting_response_packet
 end
end
 
 
EM.run do
 host = '0.0.0.0'
 port = 1813
 EM.epoll
 EM.open_datagram_socket host, port, RadiusServer do | connection |
 end
end
