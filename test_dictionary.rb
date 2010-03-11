require 'lib/dictionary'

dict = Radius::RadiusDictionary.new

dictionary_path="./dictionaries"

Dir::foreach dictionary_path do |entry|
 if entry!="." && entry!=".."
   dict.load(dictionary_path+"/"+entry)
   end
end

dict.get_vsa_type_by_id(22736,101)