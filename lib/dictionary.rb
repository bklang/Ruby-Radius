#  Radius Dictionary Loader (c) 2010 Eric Tamme
#  This is a hack and slash reworking of Rafael R. Sevilla's
#  ruby-radius project.  I might be missing someting... but
#  I couldnt get Rafael's dictionary loader to work with any
#  I had, and the code was awful, so I simplified and rewrote it.

module Radius

  class Dictionary
    def initialize
      @dictionary = { 0 => { :name => "RFC" },
                      "RFC" => 0 }
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
          vendor = get_vendor_name_by_id(vendor_id)

          @dictionary[vendor_id][number] = {}
          @dictionary[vendor_id][number][:name] = name
          @dictionary[vendor_id][number][:type] = type
          @dictionary[vendor_id][name] = number

          if orphan_values.has_key?(number)
            @dictionary[vendor_id][number][:values] = orphan_values.delete(number)
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
            @dictionary[vendor_id][attr][:values] = {
              value_id => value_name,
              value_name => value_id
            }
          rescue
            # The attribute must not have yet been defined.  Stash it for now
            # and add it when we eventually parse the attribute.
            orphan_values[attr] = {}
            orphan_values[attr][value_id] = value_name
            orphan_values[attr][value_name] = value_id
          end
        end
      end

      puts "Warning: Orphan values detected in #{dictionary_file}" if orphan_values.length > 0

    end

    def get_attribute_type_by_id(vendor_id, attribute_id)
       if @dictionary[vendor_id]!=nil &&  @dictionary[vendor_id][attribute_id]!=nil
         @dictionary[vendor_id][attribute_id][:type]
       else
         return "string"
       end
    end

    def get_attribute_name_by_id(vendor_id,attribute_id)
      if @dictionary[vendor_id]!=nil &&  @dictionary[vendor_id][attribute_id]!=nil
        @dictionary[vendor_id][attribute_id][:name]
      else
        raise "unknown attribute"
      end
    end

    def get_vendor_name_by_id(vendor_id)
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
      if vendor.class == "String"
        # Look up the vendor ID by name
        vendor = vendor_num(vendor) or raise "unknown vendor"
      end

      raise "unknown attribute: #{attr}, #{vendor}" if @dictionary[vendor][attr].nil?
      @dictionary[vendor][attr]
    end

    def vendor_num(vendor)
      @dictionary[vendor]
    end

    def attr_type(attr, vendor = 0)
      if vendor.class == "String"
        # Look up the vendor ID by name
        vendor = @dictionary[vendor] or raise "unknown vendor"
      end

      if attr.class == "String"
        # Look up the attribute ID by name
        attr = attr_num(attr, vendor)
      end

      @dictionary[vendor][attr][:type]
    end

    def attr_has_val?(attr)
      vsattr_has_val(attr, 0)
    end

    def vsattr_has_val(attr, vendor = 0)
      if vendor.class == "String"
        # Look up the vendor ID by name
        vendor = @dictionary[vendor] or raise "unknown vendor"
      end

      if attr.class == "String"
        # Look up the attribute ID by name
        attr = attr_num(attr, vendor)
      end

      @dictionary[vendor][attr].has_key?(:values)
    end

    def val_num(attr, code)
      vsaval_num(attr, 0, code)
    end

    def vsaval_num(attr, vendor, code)
      if vendor.class == "String"
        # Look up the vendor ID by name
        vendor = @dictionary[vendor] or raise "unknown vendor"
      end

      if attr.class == "String"
        # Look up the attribute ID by name
        attr = attr_num(attr, vendor)
      end

      raise "Unknown code" if @dictionary[vendor][attr][:values][code].nil?
      @dictionary[vendor][attr][:values][code]
    end

  end

end
