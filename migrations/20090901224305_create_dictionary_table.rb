class CreateDictionaryTable < ActiveRecord::Migration
  def self.up
    create_table :dictionary do |t|  
       t.column :vendorId, :integer
       t.column :attributeId, :integer
       t.column :attributeName, :string
    end  

  end

  def self.down
    raise ActiveRecord::IrreversibleMigration
      drop_table :radius
  end
end
