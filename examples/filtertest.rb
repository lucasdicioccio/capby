
require 'rubygems'
require 'capby'

include Capby

if Device.all.empty?
        puts "No interface found, maybe you should run that as root"
        exit
end

if ARGV.empty?
        puts "usage 'test.rb <ifacename>'"
        puts "\tavail. ifaces: #{Device.all.collect{|d| d.name}.join(" ")}"
        exit
end

dev = Device.all.find {|dev| dev.name == ARGV[0]}

l = LiveCapture.new(dev)
l.blocking = true

l.filter = 'tcp'

l.each(10) do |pkt|
  p pkt
end
