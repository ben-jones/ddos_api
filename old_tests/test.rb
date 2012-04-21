
#test class to test some ideas out
module Debug
  def hello
    puts "testing"
    self.hello
  end
  def stuff
    puts "hello"
  end
end

class Testing
  include Debug
  def hello
    puts "works"
  end
  
end

