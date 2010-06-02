#!/usr/bin/env ruby

capname = ARGV[0]
capname ||= 'dumpexample.cap'

begin
        require 'capby'
rescue LoadError
        require '../capby.so'
end

include Capby


cap = Capby::FileCapture.new(capname)

puts "next"
puts cap.next.timestamp.usec

puts "each"
cap.each(10) do |pkt|
        puts pkt.timestamp.usec
end

puts "while with next"
while (pkt = cap.next)
        puts pkt.timestamp.usec
end

puts "with enumerator"
en = Enumerator.new( Capby::FileCapture.new(capname), :each, 100 )

en.each do |pkt|
        puts pkt
end
