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
        # The code field is returned as a string.  As of this writing, the
    # following codes are recognized:
    #
    #   Access-Request          Access-Accept
    #   Access-Reject           Accounting-Request
    #   Accounting-Response     Access-Challenge
    #   Status-Server           Status-Client
    attr_reader :code

    # The code may be set to any of the strings described above in the
    # code attribute reader.
    attr_writer :code

    # The one-byte Identifier used to match requests and responses is
    # obtained as a character.
    attr_reader :identifier

    # The Identifer used to match RADIUS requests and responses can
    # also be directly set using this.
    attr_writer :identifier

    # The 16-byte Authenticator field can be read as a character
    # string with this attribute reader.
    attr_reader :authenticator
    # The authenticator field can be changed with this attribute
    # writer.
    attr_writer :authenticator

    # To initialize the object, pass a Radius::Dictionary object to it.
    def initialize(dict)
      @dictionary = dict
      @attributes = {}
    end

    private

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

    # I'd like to think that these methods should be built in
    # the Socket class
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

    VSA_TYPE = 26        # type given to vendor-specific attributes in RFC 2138

    def pack
      hdrlen = 1 + 1 + 2 + 16   # size of packet header
      p_hdr = "CCna16a*"        # pack template for header
      p_attr = "CCa*"           # pack template for attribute
      p_vsa = "CCNCCa*"         # pack template for VSA's
      p_vsa_3com = "CCNNa*"     # used by 3COM devices

      attstr = ""
      each_attr {
        |attr, value|
        anum = @dictionary.attr_num(attr)
        val = case @dictionary.attr_type(anum).downcase
              when "string" then value
              when "integer"
                [@dictionary.attr_has_val?(anum) ?
                 @dictionary.val_num(anum, value) : value].pack("N")
              when "ipaddr" then [inet_aton(value)].pack("N")
              when "date" then [value].pack("N")
              when "time" then [value].pack("N")
              else
                next
              end
        attstr += [@dictionary.attr_num(attr), val.length + 2, val].pack(p_attr)
      }

      # Pack vendor-specific attributes
      each_vsa {
        |vendor, attr, datum|
        vsattr_num = @dictionary.vsattr_num(vendor, attr)
        vval = case @dictionary.vsattr_type(vendor, attr)
               when "string" then datum
               when "integer"
                 @dictionary.vsattr_has_val(vendor, vsattr_num) ?
                 [@dictionary.vsaval_num(vendor, vsattr_num, datum)].pack("N") :
                   [datum].pack("N")
               when "ipaddr" then inet_aton(datum)
               when "time" then [datum].pack("N")
               else next
               end
        if vendor == 429
          # For 3COM devices
          attstr += [VSA_TYPE, vval.length + 10, vendor,
            @dictionary.vsattr_num(vendor, attr), vval].pack(p_vsa_3com)
        else
          attstr += [VSA_TYPE, vval.length + 8, vendor,
            @dictionary.vsattr_num(vendor, attr), vval.length + 2,
            vval].pack(p_vsa)
        end
      }

      return([CODES[@code], @identifier, attstr.length + hdrlen,
               @authenticator, attstr].pack(p_hdr))
    end

    # unpacks raw radius data contents so
    # it can be analyzed with other methods
    def unpack(data)
      p_hdr = "CCna16a*"

      rcodes = CODES.invert

      @code, @identifier, @length, @authenticator, attribute_data = data.unpack(p_hdr)
      @code = rcodes[@code]
  #  This should obviously not be hardcoded
      @secret="imgradius"

      while (attribute_data.length > 0)
        # read the length of the packet data
        length = attribute_data.unpack("xC")[0].to_i
        # read the type header to determine if this is a vsa
        type_id, value = attribute_data.unpack("Cxa#{length-2}")
        type_id = type_id.to_i

        if (type_id == VSA_TYPE)
          # handle vendor-specific attributes
          vendor_id, vendor_attribute_id, vendor_attribute_length = value.unpack("NCC")
          vendor_attribute_value = value.unpack("xxxxxxa#{vendor_attribute_length - 2}")[0]

          # look up the type of data so we know how to unpack it: string, int etc.
          type = @dictionary.get_attribute_type_by_id(vendor_id, vendor_attribute_id)
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
              raise "Unknown type found: #{vendor_attribute_id}"
          end
          vendor = @dictionary.get_vendor_name_by_id(vendor_id)
          attr = @dictionary.get_attribute_name_by_id(vendor_id, vendor_attribute_id)
          set_attributes({:vendor => vendor, :name => attr, :value => val})
        else
          # This is not a vendor specific attribute
          type = @dictionary.get_attribute_type_by_id(0, type_id) # 0 is the "default" vendor id
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
          set_attributes({ :number => type_id, :value => val })
        end
        attribute_data[0, length] = ""
      end
      
    end

    def set_attributes(*args)
      args.each { |attr|
        if !(attr.has_key?(:name) || attr.has_key?(:number))
          raise ArgumentError, "Must supply :name or :number"
        end
        if !attr.has_key?(:value)
          raise ArgumentError, "Must supply :value"
        end
        if !attr.has_key?(:vendor)
          attr[:vendor] = 0
        end
        if !attr.has_key?(:number)
          attr[:number] = @dictionary.attr_num(attr[:name])
        end
        if (@attributes[attr[:vendor]].nil?)
          @attributes[attr[:vendor]] = {}
        end
        
        @attributes[attr[:vendor]][attr[:number]] = attr[:value]
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
      content=""
      content+="Code: #{@code}\n"
      content+="Identifier: #{@identifier}\n"
      content+="Length: #{@length}\n"
      content+="Request Authenticator: #{@authenticator}\n"
      content+="Response Authenticator: #{get_response_authenticator()}\n"
      @attributes.each_pair do |vendor_id, vattrs|
        vattrs.each_pair do |attribute,value|
          attribute = @dictionary.get_attribute_name_by_id(vendor_id, attribute)
          # TODO convert enumerated values back to strings
          content+="#{attribute}: #{value}\n"
        end
      end
      content
    end

    # This method is provided a block which will pass every
    # attribute-value pair currently available.
    def each_attr
      @attributes.each_pair {
        |key, value|
        yield(key, value)
      }
    end

    # This method will pass each vendor-specific attribute available
    # to a passed block.  The parameters to the block are the vendor
    # ID, the attribute name, and the attribute value.
    def each_vsa
      @vsattributes.each_index {
        |vendorid|
        if @vsattributes[vendorid] != nil
          @vsattributes[vendorid].each_pair {
            |key, value|
            value.each {
              |val|
              yield(vendorid, key, val)
            }
          }
        end
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


