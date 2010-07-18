#  Radius Dictionary Loader (c) 2010 Eric Tamme
#  This is a hack and slash reworking of Rafael R. Sevilla's
#  ruby-radius project.  I might be missing someting... but
#  I couldnt get Rafael's dictionary loader to work with any
#  I had, and the code was awful, so I simplified and rewrote it.

module Radius

  class Dictionary
    def initialize(dictionary_file)
      @dictionary = { 0 => { :name => "RFC" },
                      "RFC" => 0 }
      load(dictionary_file)
    end

    def load(dictionary_file)
      # set the default vendor id
      vendor_id=0

      # Temporary holding spot for values being defined that have not yet had
      # their attributes defined.
      orphan_values = {}

      File.open(dictionary_file, "r").each_line do |line|

        next if line =~ /^\#/    # discard comments
        next if (tokens = line.split(/\s+/)) == []

        token=tokens[0].upcase

        case token
        when "$INCLUDE"
          #Example lines
          #$INCLUDE        /usr/share/freeradius/dictionary

          # This is a FreeRADIUS-style file inclusion directive
          linetype, file = tokens
          file.strip!

          # Load the referenced file by calling this function recursively
          if file =~ /^\//
            # File names with a leading slash are absolute
            load(tokens[1])
          else
            # File names without a leading slash are relative
            # to the current file
            load(File.dirname(dictionary_file) + "/" + file)
          end

        when "VENDOR"
          #Example line
          #VENDOR    Digium        22736

          # Setup a new hash to hold attributes and values for the vendor id
          linetype, name, id = tokens
          name.strip!
          id = id.to_i

          if @dictionary[id].nil?
            @dictionary[id] = { :name => name }
            @dictionary[name] = id
          end

        when "BEGIN-VENDOR"
          #Example lines
          #BEGIN-VENDOR Digium

          # We have a new active vendor ID for the following attributes
          linetype, name = tokens
          name.strip!
          vendor_id = @dictionary[name]
          raise "Parse error: unknown vendor" if vendor_id.nil?

        when "END-VENDOR"
          #Example lines
          #END-VENDOR Digium

          # We've reached the end of this vendor's definitions.  Reset to the
          # no-vendor vendor ID.
          vendor_id = 0

        when "ATTRIBUTE"
          #Example lines
          #ATTRIBUTE       Asterisk-Acc-Code               101     string  Digium
          #ATTRIBUTE	   Acct-Delay-Time		           41	   integer
          linetype, name, number, type = tokens
          name.strip!
          number = number.to_i
          type.strip!
          type.downcase!
          vendor = vendor_name(vendor_id)

          @dictionary[vendor_id][number] = {}
          @dictionary[vendor_id][number][:name] = name
          @dictionary[vendor_id][number][:type] = type
          @dictionary[vendor_id][name] = number

          if orphan_values.has_key?(number)
            # Initialize the values if some do not already exist
            if @dictionary[vendor_id][number][:values].nil?
              @dictionary[vendor_id][number][:values] = {}
            end
            @dictionary[vendor_id][number][:values].merge!(orphan_values.delete(number))
          end

        when "VALUE"
          #Example line
          #VALUE		Service-Type	Callback-Login-User	3

          # These are enumerables.  The name of the value matches the name of
          # an attribute, and (only?) the defined values are legal

          #Store a name key, and an id key
          linetype, attr, value_name, value_id = tokens
          attr.strip!
          value_name.strip!
          value_id = value_id.to_i
          begin
            attr = attr_num(attr, vendor_id)
            if @dictionary[vendor_id][attr][:values].nil?
              @dictionary[vendor_id][attr][:values] = {}
            end
            @dictionary[vendor_id][attr][:values].merge!({
              value_id => value_name,
              value_name => value_id
            })
          rescue
            # The attribute must not have yet been defined.  Stash it for now
            # and add it when we eventually parse the attribute.
            if orphan_values[attr].nil?
              orphan_values[attr] = {}
            end
            orphan_values[attr][value_id] = value_name
            orphan_values[attr][value_name] = value_id
          end
        end
      end

      puts "Warning: Orphan values detected in #{dictionary_file}" if orphan_values.length > 0

    end

    def attr_type(vendor_id, attribute_id)
      #FIXME: allow looking up by name
       if @dictionary[vendor_id]!=nil &&  @dictionary[vendor_id][attribute_id]!=nil
         @dictionary[vendor_id][attribute_id][:type]
       else
         return "string"
       end
    end

    def attr_name(vendor_id,attribute_id)
      if @dictionary[vendor_id]!=nil &&  @dictionary[vendor_id][attribute_id]!=nil
        @dictionary[vendor_id][attribute_id][:name]
      else
        raise "unknown attribute"
      end
    end

    def vendor_name(vendor_id)
      vendor_id = vendor_id.to_i
      if @dictionary[vendor_id]!=nil
        @dictionary[vendor_id][:name]
      else
        raise "unknown vendor: #{vendor_id}"
      end
    end

    def vendor_id(name)
      @dictionary[name]
    end

    def attr_num(attr, vendor = 0)
      if vendor.class == String
        # Look up the vendor ID by name
        vendor = vendor_num(vendor)
      end

      raise "unknown attribute: #{attr}, #{vendor}" if @dictionary[vendor][attr].nil?
      @dictionary[vendor][attr]
    end

    def vendor_num(vendor)
      @dictionary.has_key?(vendor) or raise "unknown vendor"
      @dictionary[vendor]
    end

    def attr_type(attr, vendor = 0)
      if vendor.class == String
        # Look up the vendor ID by name
        vendor = @dictionary[vendor] or raise "unknown vendor"
      elsif !@dictionary.has_key?(vendor)
        raise "Unknown vendor #{vendor}"
      end

      if attr.class == String
        # Look up the attribute ID by name
        attr = attr_num(attr, vendor)
      elsif !@dictionary[vendor].has_key?(attr)
        puts "Warning: Unknown attribute #{attr} for vendor #{vendor}"
        return "string"
      end

      @dictionary[vendor][attr][:type]
    end

    def attr_has_val?(attr)
      vsattr_has_val?(attr, 0)
    end

    def vsattr_has_val?(attr, vendor = 0)
      if vendor.class == String
        # Look up the vendor ID by name
        vendor = vendor_num(vendor)
      elsif !@dictionary.has_key?(vendor)
        raise ArgumentError, "Unknown vendor #{vendor}"
      end

      if attr.class == String
        # Look up the attribute ID by name
        attr = attr_num(attr, vendor)
      elsif !@dictionary[vendor].has_key?(attr)
        raise ArgumentError, "Unknown attribute #{attr} for vendor #{vendor}"
      end

      @dictionary[vendor][attr].has_key?(:values)
    end

    def val_convert(attr, code)
      vsaval_convert(attr, 0, code)
    end

    def vsaval_convert(attr, vendor, code)
      if vendor.class == String
        # Look up the vendor ID by name
        vendor = vendor_num(vendor)
      end

      if attr.class == String
        # Look up the attribute ID by name
        attr = attr_num(attr, vendor)
      end

      raise "Unknown value: Vendor #{vendor} Attr #{attr} Code #{code}" if @dictionary[vendor][attr][:values][code].nil?
      @dictionary[vendor][attr][:values][code]
    end
  end
end
