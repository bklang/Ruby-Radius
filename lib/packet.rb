#  Radius Packet Decoder (c) 2010 Eric Tamme
#  This is a hack and slash reworking of Rafael R. Sevilla's
#  ruby-radius project.  I couldn't get his dictionary to work
#  and I only care about recieving radius accounting records
#  so this code has been ripped and stripped of all non
#  essential functionality for sake of clarity

module Radius
  require 'digest/md5'
  require 'lib/dictionary'

  class Packet

    CODES = {
        'Access-Request' => 1,
        'Access-Accept' => 2,
        'Access-Reject' => 3,
        'Accounting-Request' => 4,
        'Accounting-Response' => 5,
        'Access-Challenge' => 11,
        'Status-Server' => 12,
        'Status-Client' => 13
    }

    VSA_TYPE = 26        # type given to vendor-specific attributes in RFC 2138

    # The one-byte Identifier used to match requests and responses is
    # obtained as a character.
    attr_accessor :identifier

    # The 16-byte Authenticator field can be read as a character string
    attr_accessor :authenticator

    attr_accessor :dictionary

    attr_reader :fromaddr

    attr_accessor :toaddr

    # To initialize the object, pass a Radius::Dictionary object to it.
    def initialize(dict, secret, radhost = nil)
      if dict.class == String
        # Treat this as the path to a dictionary file and try to load it.
        @dictionary = Radius::Dictionary.new(dict)
      elsif dict.class == Radius::Dictionary
        @dictionary = dict
      else
        raise ArgumentError, "Must provide a valid dictionary."
      end

      @attributes = {}
      @code = nil
      @secret = secret

      if !radhost.nil?
        @host, @port = radhost.split(":")
        @port = Socket.getservbyname("radius", "udp") unless @port
        @port = 1812 unless @port
        @port = @port.to_i	# just in case
      end
    end

    # unpacks raw radius data contents so
    # it can be analyzed with other methods
    # Returns a new instance of Radius::Packet
    def self.unpack(dictionary, data, secret)
      p = Radius::Packet.new(dictionary, secret)

      p_hdr = "CCna16a*"

      p.code, p.identifier, length, p.authenticator, attribute_data = data.unpack(p_hdr)

      while (attribute_data.length > 0)
        # read the length of the packet data
        alength = attribute_data.unpack("xC")[0].to_i
        # read the type header to determine if this is a vsa
        type_id, value = attribute_data.unpack("Cxa#{alength-2}")
        type_id = type_id.to_i

        if (type_id == VSA_TYPE)
          # handle vendor-specific attributes
          vendor_id, vendor_attribute_id, vendor_attribute_length = value.unpack("NCC").map{ |v| v.to_i }
          vendor_attribute_value = value.unpack("xxxxxxa#{vendor_attribute_length - 2}")[0]

          # look up the type of data so we know how to unpack it: string, int etc.
          type = p.dictionary.attr_type(vendor_attribute_id, vendor_id)
          if type == nil
            raise "Garbled vendor-specific attribute #{vendor_id}/#{vendor_attribute_id}"
          end

          val = case type
            when 'string' then
              vendor_attribute_value
            when 'integer' then
              vendor_attribute_value.unpack("N")[0]
            when 'ipaddr' then
              inet_ntoa(vendor_attribute_value)
            when 'time' then
              vendor_attribute_value.unpack("N")[0]
            when 'date' then
              vendor_attribute_value.unpack("N")[0]
            else
              puts "Unknown type found: #{type}"
          end
          vendor = p.dictionary.vendor_name(vendor_id)
          attr = p.dictionary.attr_name(vendor_id, vendor_attribute_id)
          p.set_attributes({:vendor => vendor, :attr => attr, :value => val})
        else
          # This is not a vendor specific attribute
          type = p.dictionary.attr_type(0, type_id) # 0 is the "default" vendor id
          raise "Garbled attribute #{type_id}" if (type == nil)
          val = case type
            when 'string' then
              value
            when 'integer' then
              value.unpack("N")[0]
            when 'ipaddr' then
              inet_ntoa(value.unpack("N")[0])
            when 'time' then
              value.unpack("N")[0]
            when 'date' then
              value.unpack("N")[0]
            else
              raise "Unknown attribute type found: #{type}"
          end
          p.set_attributes({ :attr => type_id, :value => val })
        end
        attribute_data[0, alength] = ""
      end

      # Return the parsed packet
      p
    end

    # The code field is returned as a string.  As of this writing, the
    # following codes are recognized:
    #
    #   Access-Request          Access-Accept
    #   Access-Reject           Accounting-Request
    #   Accounting-Response     Access-Challenge
    #   Status-Server           Status-Client
    def code=(code)
      if CODES.has_key?(code)
        @code = code
      elsif CODES.invert.has_key?(code)
        @code = CODES.invert[code]
      else
        raise ArgumentError, "Invalid packet code #{code}"
      end
    end

    def code
      @code
    end


    private

    def gen_authenticator(packetlen = nil)

    end

    # I'd like to think that these methods should be built in
    # the Socket class
    # FIXME: Use IPAddr class (http://www.ruby-forum.com/topic/58191)
    def inet_aton(hostname)
      if (hostname =~ /([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/)
        return((($1.to_i & 0xff) << 24) + (($2.to_i & 0xff) << 16) +
                (($3.to_i & 0xff) << 8) + (($4.to_i & 0xff)))
      end
      return(0)
    end

    def inet_ntoa(iaddr)
      return(sprintf("%d.%d.%d.%d", (iaddr >> 24) & 0xff, (iaddr >> 16) & 0xff,
                     (iaddr >> 8) & 0xff, (iaddr) & 0xff))
    end

    public

    # Sends a packet to the server via UDP.
    def send(timeout = 5)
      sock = UDPSocket.open
      sock.connect(@host, @port)
      data = self.pack
      @identifier = (@identifier + 1) & 0xff
      # def send(mesg, flags, *rest)
      sock.send(data, 0)
      # Return the socket so it can be read
      sock
    end


    def pack
      if (@code.nil? || @identifier.nil? || @attributes.empty?)
        raise ArgumentError, "Must specify all required packet information: code, identifier, attributes"
      end

      hdrlen = 1 + 1 + 2 + 16   # size of packet header
      p_hdr = "CCna16a*"        # pack template for header
      p_attr = "CCa*"           # pack template for attribute
      p_vsa = "CCNCCa*"         # pack template for VSA's
      p_vsa_3com = "CCNNa*"     # used by 3COM devices

      attstr = ""
      each_attr { |attr, value|
        attr = @dictionary.attr_num(attr) if attr.class == String
        val = case @dictionary.attr_type(attr).downcase
              when "string" then value
              when "integer"
                [@dictionary.attr_has_val?(attr) && value.class == String ?
                 @dictionary.val_convert(attr, value) : value].pack("N")
              when "ipaddr" then [inet_aton(value)].pack("N")
              when "date" then [value].pack("N")
              when "time" then [value].pack("N")
              else
                next
              end
        attstr += [attr, val.length + 2, val].pack(p_attr)
      }

      # Pack vendor-specific attributes
      each_vsa { |vendor, attr, value|
        vsattr_num = @dictionary.attr_num(attr, vendor)
        vval = case @dictionary.attr_type(attr, vendor)
               when "string" then value
               when "integer"
                 @dictionary.vsattr_has_val?(vendor, vsattr_num) && value.class == String ?
                 [@dictionary.vsaval_convert(vendor, vsattr_num, value)].pack("N") :
                   [value].pack("N")
               when "ipaddr" then inet_aton(value)
               when "time" then [value].pack("N")
               else next
               end
        if vendor == 429
          # For 3COM devices
          attstr += [VSA_TYPE, vval.length + 10, vendor,
            attr, vval].pack(p_vsa_3com)
        else
          attstr += [VSA_TYPE, vval.length + 8, vendor,
            attr, vval.length + 2,
            vval].pack(p_vsa)
        end
      }

      case @code
      when "Access-Request"
        # According to RFC 2138:
        # In Access-Request Packets, the Authenticator value is a 16 octet
        # random number, called the Request Authenticator.  The value SHOULD
        # be unpredictable and unique over the lifetime of a secret (the
        # password shared between the client and the RADIUS server)

        # get authenticator data from /dev/urandom if possible
        if (File.exist?("/dev/urandom"))
          File.open("/dev/urandom") { |urandom|
            authenticator = urandom.read(16)
          }
        else
          # use the Kernel:rand method.  This is quite probably not
          # as secure as using /dev/urandom, be wary...
          authenticator = [rand(65536), rand(65536), rand(65536),
            rand(65536), rand(65536), rand(65536), rand(65536),
            rand(65536)].pack("n8")
        end

      when "Accounting-Request"
        # According to RFC 2866:
        # In Accounting-Request Packets, the Authenticator value is a 16
        # octet MD5 [5] checksum, called the Request Authenticator.

        # The NAS and RADIUS accounting server share a secret.  The Request
        # Authenticator field in Accounting-Request packets contains a one-
        # way MD5 hash calculated over a stream of octets consisting of the
        # Code + Identifier + Length + 16 zero octets + request attributes +
        # shared secret (where + indicates concatenation).  The 16 octet MD5
        # hash value is stored in the Authenticator field of the
        # Accounting-Request packet.

        # Note that the Request Authenticator of an Accounting-Request can
        # not be done the same way as the Request Authenticator of a RADIUS
        # Access-Request, because there is no User-Password attribute in an
        # Accounting-Request.
#puts [CODES[@code], @identifier, attstr.length + hdrlen, nil, attstr].pack(p_hdr).unpack('H*')
        authenticator = Digest::MD5.digest([CODES[@code], @identifier, attstr.length + hdrlen,
                        nil, attstr].pack(p_hdr))
#puts authenticator.unpack('H*')
      end

      @data = [CODES[@code], @identifier, attstr.length + hdrlen,
               authenticator, attstr].pack(p_hdr)
    end

    def set_attributes(*args)
      args.each { |item|
        if !item.has_key?(:attr)
          raise ArgumentError, "Must supply :attr"
        end
        if !item.has_key?(:value)
          raise ArgumentError, "Must supply :value"
        end

        # Default to the no-vendor number
        if !item.has_key?(:vendor)
          item[:vendor] = 0
        end

        # Look up the vendor's number
        if item[:vendor].class == String
          item[:vendor] = @dictionary.vendor_num(item[:vendor])
        end

        # Look up the attribute number
        if item[:attr].class == String
          item[:attr] = @dictionary.attr_num(item[:attr], item[:vendor])
        end

        # Initialize the vendor's place in the attribute hash
        if (@attributes[item[:vendor]].nil?)
          @attributes[item[:vendor]] = {}
        end

        # Look up the value number for enumerated values
        if (@dictionary.vsattr_has_val?(item[:attr], item[:vendor]))
          item[:value] = @dictionary.vsaval_convert(item[:attr], item[:vendor], item[:value])
        end

        @attributes[item[:vendor]][item[:attr]] = item[:value]
      }
    end

    def get_accounting_response_packet
       hdrlen = 1 + 1 + 2 + 16 # size of packet header
       p_hdr = "CCna16a*" # pack template for header
       attributes=""
       packet=[5, @identifier, attributes.length + hdrlen,get_response_authenticator, attributes].pack(p_hdr)
    end

    def get_response_authenticator
       hdrlen = 1 + 1 + 2 + 16 # size of packet header
       p_hdr = "CCna16a*" # pack template for header
       attributes=""
       hash_data=[5, @identifier, attributes.length + hdrlen,@authenticator, attributes,@secret].pack(p_hdr)
       digest = Digest::MD5.digest(hash_data)
    end

    def to_s
      content="-------- Radius::Packet --------\n"
      content+="Code: #{@code}\n"
      content+="Identifier: #{@identifier}\n"
      content+="Length: #{@length}\n" if @length
      #content+="Request Authenticator: #{@authenticator}\n"
      #content+="Response Authenticator: #{get_response_authenticator()}\n"
      @attributes.each_pair do |vendor_id, vattrs|
        vattrs.each_pair do |attribute,value|
          if @dictionary.vsattr_has_val?(attribute, vendor_id)
            value = @dictionary.vsaval_convert(attribute, vendor_id, value)
          end
          attribute = @dictionary.attr_name(vendor_id, attribute)
          content+="#{attribute}: #{value}\n"
        end
      end
      content+="\n"
    end

    # This method is provided a block which will pass every
    # attribute-value pair currently available.
    def each_attr
      @attributes[0].each_pair { |key, value|
        yield(key, value)
      }
    end

    # This method will pass each vendor-specific attribute available
    # to a passed block.  The parameters to the block are the vendor
    # ID, the attribute name, and the attribute value.
    def each_vsa
      @attributes.each { |vendorid, vsattrs|
        next if vendorid == 0
        vsattrs.each_pair { |key, value|
          yield(vendorid, key, value)
        }
      }
    end

    # The RADIUS User-Password attribute is encoded with a shared
    # secret.  This method will prepare the encoded version of the
    # password.  Note that this method <em>always</em> stores the
    # encrypted password in the 'User-Password' attribute.  Some
    # (non-RFC 2138-compliant) servers have been reported that insist
    # on using the 'Password' attribute instead.
    #
    # ====Parameters
    # +passwd+:: The password to encrypt
    # +secret+:: The shared secret of the RADIUS system
    #
    def set_password(pwdin, secret)
      lastround = @authenticator
      pwdout = ""
      # pad to 16n bytes
      pwdin += "\000" * (15-(15 + pwdin.length) % 16)
      0.step(pwdin.length-1, 16) {
        |i|
        lastround = xor_str(pwdin[i, 16],
                            Digest::MD5.digest(secret + lastround))
        pwdout += lastround
      }
      set_attr("User-Password", pwdout)
      return(pwdout)
    end
  end
end
