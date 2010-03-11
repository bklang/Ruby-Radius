#  Radius Packet Decoder (c) 2010 Eric Tamme
#  This is a hack and slash reworking of Rafael R. Sevilla's
#  ruby-radius project.  I couldn't get his dictionary to work
#  and I only care about recieving radius accounting records
#  so this code has been ripped and stripped of all non
#  essential functionality for sake of clarity

module Radius
  require 'digest/md5'
  require 'dictionary'

  class Packet
    # To initialize the object, pass a Radius::Dictionary object to it.
    def initialize(dict)
      @dictionary = dict
      @attributes = {}
    end

    private
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

    # unpacks raw radius data contents so
    # it can be analyzed with other methods
    def unpack(data)
      p_hdr = "CCna16a*"
      rcodes = {
              1 => 'Access-Request',
              2  => 'Access-Accept',
              3  => 'Access-Reject',
              4  => 'Accounting-Request',
              5  => 'Accounting-Response',
              11 => 'Access-Challenge',
              12 => 'Status-Server',
              13 => 'Status-Client'
      }

      @code, @identifier, len, @authenticator, attribute_data = data.unpack(p_hdr)
      @code = rcodes[@code]

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
          type = @dictionary.get_vsa_type_by_id(vendor_id, vendor_attribute_id)
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
          set_attribute(vendor_id,attribute_id,val)
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
          set_attribute(0,type_id,val)
        end
      end
    end

    def set_attribute(vendor_id,attribute_id,value)
        attribute_name=@dictionary.get_attribute_name_by_id(vendor_id,attribute_id)
        @attributes[attribute_name]=value
    end

    def to_s
      content=""
      @attributes.each_pair do |attribute,value|
         content+="#{attribute}: #{value}\n"
      end
      content
    end

  end
  end


