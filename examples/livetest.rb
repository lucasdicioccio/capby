#!/usr/bin/env ruby
require 'time'
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
puts l.datalink
puts l.filter
l.filter = ''
puts l.filter

puts l.instance_variable_get(:@direction)

begin
  puts l.direction
  l.direction = :in
  puts l.direction
  l.direction = :out
  puts l.direction
  l.direction = :both
  puts l.direction
rescue CapbyError
  puts "cannot set direction on this platform"
end

puts "set immediate tests"
puts l.immediate!(true) 
puts "set blocking tests"
puts l.blocking?
l.blocking= false
puts l.blocking?
l.blocking= true
puts l.blocking?

Thread.new do 
  loop do
    sleep 5
    puts "hello from thread: #{Time.now}"
  end
end

puts "waiting next packet"
puts l.next.timestamp

begin
  Enumerator
rescue NameError
  include Enumerable
end

loop do
  enum = Enumerator.new(l, :each, 20)
  enum.each do |pkt|
    puts "got #{pkt.data.length} bytes at #{pkt.timestamp}" if pkt
  end
  p l.stats
end

