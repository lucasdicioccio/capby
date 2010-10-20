require 'mkmf'

$CFLAGS ||= ''
$LDFLAGS ||= ''

if RUBY_PLATFORM =~ /i386-(mingw|syswin)32/
	adefdir = ['/WpdPack']
	adefinc = adefdir + ['/Include']
	adeflib = adefdir + ['/Lib']

	defdir = File.expand_path(File.join(adefdir))
	deflib = File.expand_path(File.join(adeflib))
	definc = File.expand_path(File.join(adefinc))

	puts defdir
	puts deflib
	puts definc

        wpdpack_dir = with_config('pcap-dir', defdir)
        wpdpack_includedir = with_config('pcap-includedir', definc)
        wpdpack_libdir = with_config('pcap-libdir', deflib)

	puts wpdpack_dir
	puts wpdpack_includedir
	puts wpdpack_libdir

        $CFLAGS += " -DWIN32 -I #{wpdpack_includedir} "
        $LDFLAGS += " -L #{wpdpack_libdir} "

	puts $CFLAGS
	puts $LDFLAGS
        exit unless have_library("wpcap", "pcap_open_live")
	have_func("Sleep")
	have_func("QueryPerformanceCounter")
else
        have_header("pcap.h")
        have_library("pcap", "pcap_open_live")
end

if RUBY_PLATFORM =~ /java/
  $CFLAGS += " -DJRUBY"
end
if RUBY_VERSION =~ /1.9/
  $CFLAGS += " -DRUBY_19"
end

if have_header("rubysig.h")
  $CFLAGS += " -DHAVE_TRAP_BEG_M" if have_macro("TRAP_BEG", "rubysig.h")
  $CFLAGS += " -DHAVE_TRAP_END_M" if have_macro("TRAP_END", "rubysig.h")
end

have_type("struct pcap_stat", "pcap.h")
have_type("struct timespec")
have_struct_member("struct pcap_stat","bs_capt") 
have_func("pcap_get_selectable_fd")
have_func("pcap_set_snaplen")
have_func("pcap_set_buffer_size")
have_func("pcap_set_timeout")
have_func("pcap_setmintocopy")
have_func("nanosleep")
have_func("pcap_inject")
have_func("pcap_next_ex")
have_func("pcap_sendpacket")
have_func("pcap_setdirection")
have_func("rb_thread_wait_fd")
have_func("rb_equal")
have_header("dnet.h")
have_header("net/bpf.h")
if have_macro("BIOCIMMEDIATE", "net/bpf.h")
        $CFLAGS += " -DHAVE_BIOCIMMEDIATE"
end
have_library("dnet", "arp_open")

create_makefile("capby_api")
