#!/usr/bin/env ruby
require 'time'
require 'capby.so'

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

pkts = (0 .. 10).map{|i| Packet.new("a"*1500)}
pkts.each {|pkt| pkt.send_on(l) }
