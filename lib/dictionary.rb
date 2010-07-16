#  Radius Dictionary Loader (c) 2010 Eric Tamme
#  This is a hack and slash reworking of Rafael R. Sevilla's
#  ruby-radius project.  I might be missing someting... but
#  I couldnt get Rafael's dictionary loader to work with any
#  I had, and the code was awful, so I simplified and rewrote it.

module Radius

  class Dictionary
    def initialize
      @dictionary={}
      @dictionary[0]={}
      @dictionary[0]["ATTRIBUTES"]={}
      @dictionary[0]["VALUES"]={}
    end

    def load(dictionary_file)
      # set the default vendor id
      vendor_id=0
      File.open(dictionary_file, "r").each_line do |line|

        next if line =~ /^\#/    # discard comments
        next if (tokens = line.split(/\s+/)) == []

        token=tokens[0].upcase

        case token
          when "$INCLUDE"
            # This is a FreeRADIUS-style file inclusion directive
            load(tokens[1])

          when "VENDOR"    # Setup a new hash to hold attributes and values for the vendor id
            #Example line
            #VENDOR    Digium        22736

            #I am assuming that all attributes and values will belong to the last
            #"declared" vendor, until a new vendor is encountered
            vendor_id=tokens[2].to_i
            if @dictionary[vendor_id].nil?
              @dictionary[vendor_id]={}
              @dictionary[vendor_id]["ATTRIBUTES"]={}
              @dictionary[vendor_id]["VALUES"]={}
              @dictionary[vendor_id]["NAME"]=tokens[1].strip
            end
          when "ATTRIBUTE"
            #Example lines
            #ATTRIBUTE       Asterisk-Acc-Code               101     string  Digium
            #ATTRIBUTE	   Acct-Delay-Time		           41	   integer
            @dictionary[vendor_id][tokens[2].to_i]={}
            @dictionary[vendor_id][tokens[2].to_i]["NAME"]=tokens[1].strip
            @dictionary[vendor_id][tokens[2].to_i]["TYPE"]=tokens[3].strip
            #also make a hash key of the attribute name b/c we need it to store values
            @dictionary[vendor_id][tokens[1].strip]={"ID"=>tokens[2].to_i, "TYPE"=>tokens[3].strip}
#debug            puts "#{vendor_id}[#{tokens[2].to_i}][\"TYPE\"]=>#{tokens[3]}"
          when "VALUE"
            #Example line
            #VALUE		Service-Type	Callback-Login-User	3
            #Store a name key, and an id key
            @dictionary[vendor_id][tokens[1]]={tokens[2].strip=>tokens[3].to_i}
            @dictionary[vendor_id][tokens[1]]={tokens[3].to_i=>tokens[2].strip}
        end
      end
#      puts @dictionary.inspect

    end

    def get_attribute_type_by_id(vendor_id, attribute_id)
       if @dictionary[vendor_id]!=nil &&  @dictionary[vendor_id][attribute_id]!=nil
         @dictionary[vendor_id][attribute_id]["TYPE"]
       else
         return "string"
       end
    end

    def get_attribute_name_by_id(vendor_id,attribute_id)
      if @dictionary[vendor_id]!=nil &&  @dictionary[vendor_id][attribute_id]!=nil
        @dictionary[vendor_id][attribute_id]["NAME"]
      else
        return "unknown attribute"
      end
    end

    def get_vendor_name_by_id(vendor_id)
      if @dictionary[vendor_id]!=nil
        @dictionary[vendor_id]["NAME"]
      else
        return "unknown vendor"
      end
    end

  end

end
