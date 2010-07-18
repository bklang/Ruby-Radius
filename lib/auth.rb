# RADIUS authenticator
#  Copyright (C) 2002 Rafael R. Sevilla <dido@imperium.ph>
#  This file is part of the Radius Authentication Module for Ruby
#
#  The Radius Authentication Module for Ruby is free software; you can
#  redistribute it and/or modify it under the terms of the GNU Lesser
#  General Public License as published by the Free Software
#  Foundation; either version 2.1 of the License, or (at your option)
#  any later version.
#
#  The Radius Authentication Module is distributed in the hope that it
#  will be useful, but WITHOUT ANY WARRANTY; without even the implied
#  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with the GNU C Library; if not, write to the Free
#  Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
#  02111-1307 USA.
#
# Author:: Rafael R. Sevilla (mailto:dido@imperium.ph)
# Copyright:: Copyright (c) 2002 Rafael R. Sevilla
# License:: GNU Lesser General Public License
# $Id: auth.rb 2 2006-12-17 06:16:21Z dido $
#

module Radius
  require 'lib/packet'
  require 'socket'

  class Auth
    # We can inspect and alter the contents of the internal RADIUS
    # packet here (although this is probably not required for simple
    # work)
    attr_reader :packet

    attr_reader :dictionary

    # This method initializes the Auth object, given a dictionary
    # filename to read, the RADIUS host[:port] to connect to, and a
    # timeout value in seconds for the connection.
    # =====Parameters
    # +dictfilename+:: Dictionary filename to read
    # +radhost+:: name of RADIUS server optionally followed by port number
    # +secret+:: RADIUS shared secret
    # +myip+:: the client's own IP address (NAS IP address)
    # +timeout+:: Timeout time
    def initialize(dictfilename, radhost, secret, myip, timeout = 5)
      @dict = Radius::Dictionary.new(dictfilename)
      @myip = myip
      @secret = secret
      @radhost = radhost
      @timeout = timeout
    end

    # Verifies a username/password pair against the RADIUS server
    # associated with the Auth object.
    #
    # =====Parameters
    # +name+:: The user name to verify
    # +pwd+:: The password associated with this name
    # =====Return value
    # returns true or false depending on whether or not the attempt succeeded or failed.
    def check_passwd(name, pwd = nil)
      @packet = Radius::Packet.new(@dict, @secret, @radhost + ":1812")
      # this is probably better than starting identifiers at 0
      @packet.identifier = Kernel.rand(65535)
      @packet.code = 'Access-Request'
      @packet.set_attributes({ :attr => 'User-Name', :value => name })
      @packet.set_attributes({ :attr => 'NAS-IP-Address', :value => @myip })
      # FIXME: Need to abstract this somehow
      @packet.set_attributes({ :attr => 'Calling-Station-Id', :value => "0014044754840" })
      @packet.set_attributes({ :attr => 'Called-Station-Id', :value => "0014046955106" })
      # END FIXME
      @packet.add_password(pwd, @secret) if !pwd.nil?
puts @packet.to_s
      @sock = @packet.send
      @packet = recv_packet
      @sock.close
puts @packet.to_s
      # TODO: Validate the response authenticator
      return(@packet.code == 'Access-Accept')
    end

    def start_accounting(name, session_id)
      @packet = Radius::Packet.new(@dict, @secret, @radhost + ":1813")
      # this is probably better than starting identifiers at 0
      @packet.identifier = Kernel.rand(65535)
      @packet.code = 'Accounting-Request'
      @packet.set_attributes(
        { :attr => 'User-Name', :value => name },
        { :attr => 'NAS-IP-Address', :value => @myip },
        { :attr => 'Acct-Session-Id', :value => session_id },
        { :attr => 'Acct-Status-Type', :value => 'Start' },
        { :attr => 'Acct-Authentic', :value => 'RADIUS' }
      )
      @packet.set_attributes({ :attr => 'Calling-Station-Id', :value => "0014044754840" })
      @packet.set_attributes({ :attr => 'Called-Station-Id', :value => "0014046955106" })
puts @packet.to_s
      @sock = @packet.send
      @packet = recv_packet
      @sock.close
puts @packet.to_s
      # TODO: Validate the response authenticator
      return(@packet.code == 'Accounting-Response')
    end

    def stop_accounting(name, session_id)
      @packet = Radius::Packet.new(@dict, @secret, @radhost + ":1812")
      # this is probably better than starting identifiers at 0
      @packet.identifier = Kernel.rand(65535)
      @packet.code = 'Accounting-Request'
      @packet.set_attributes(
        { :attr => 'User-Name', :value => name },
        { :attr => 'NAS-IP-Address', :value => @myip },
        { :attr => 'Acct-Session-Id', :value => session_id },
        { :attr => 'Acct-Status-Type', :value => 'Stop' },
        { :attr => 'Acct-Session-Time', :value => 0 },
        { :attr => 'Acct-Terminate-Cause', :value => "User-Request" }
      )
puts @packet.to_s
      @sock = @packet.send
      @packet = recv_packet
      @sock.close
puts @packet.to_s
      # TODO: Validate the response authenticator
      return(@packet.code == 'Accounting-Response')
    end

    protected
    # Generate an authenticator, placing it in the @packet object's
    # authenticator attribute.  It will try to use /dev/urandom if
    # possible, or the system rand call if that's not available.
    def gen_auth_authenticator
      # get authenticator data from /dev/urandom if possible
       if (File.exist?("/dev/urandom"))
        File.open("/dev/urandom") { |urandom|
          @packet.authenticator = urandom.read(16)
        }
       else
        # use the Kernel:rand method.  This is quite probably not
        # as secure as using /dev/urandom, be wary...
        @packet.authenticator = [rand(65536), rand(65536), rand(65536),
          rand(65536), rand(65536), rand(65536), rand(65536),
          rand(65536)].pack("n8")
      end
      return(@packet.authenticator)
    end

    # Receive a packet from the server via UDP.
    def recv_packet
      if select([@sock], nil, nil, @timeout) == nil
        raise "Timed out waiting for response packet from server"
      end
      data = @sock.recvfrom(65536)
      @packet = Radius::Packet.unpack(@dict, data[0], @secret)
      return(@packet)
    end
  end
end
