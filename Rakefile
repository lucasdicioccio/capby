require 'rubygems'
require 'rake/gempackagetask'

# Building the Gem
# TODO: add automatic versioning to GCC with that with CAPBY_VERSION in a config.h

def on_windows?
  RUBY_PLATFORM =~ /i386-(mingw|syswin|mswin)32/
end

spec = Gem::Specification.new do |s|
  s.name = 'capby'
  s.version = '0.5.5'
  s.platform = Gem::Platform::CURRENT
  s.summary = "Capby is a rubyesque low-level binding to libpcap"

  s.author = "Di Cioccio Lucas"
  s.email = "lucas.dicioccio<@nospam@>frihd.net"
  s.rubyforge_project = 'capby'
  s.homepage = 'http://rubyforge.org/projects/capby/'

  if on_windows?
    puts "adding precompiled file"
    s.files = ['README', 'LICENSE', 'lgpl-3.0.txt', 'Rakefile',
      'TODO', 'lib/capby.rb', 'lib/capby_api.so', 'ext/capby_api.c',
      'ext/capby.h', 'ext/extconf.rb']
  else
    s.files = ['README', 'LICENSE', 'lgpl-3.0.txt', 'Rakefile',
      'TODO', 'lib/capby.rb', 'ext/capby_api.c',
      'ext/capby.h', 'ext/extconf.rb']
    s.extensions = ['ext/extconf.rb']
  end

  s.require_path = 'lib'

  s.has_rdoc = false
end

Rake::GemPackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end

if on_windows?
  file "ext/Makefile" do
    here = File.expand_path('.')
    FileUtils.cd "ext"
    sh "ruby extconf.rb"
    FileUtils.cd here
  end

  file "lib/capby_api.so" => "ext/Makefile" do
    sh "make -C ext"
    mv "ext/capby_api.so", "lib/capby_api.so"
  end
end

task :gem => "pkg/#{spec.name}-#{spec.version}-#{spec.platform}.gem" do
  puts "Beware: unless done, should build ext in ./ext dir" if on_windows?
  puts "generated #{spec.version}"
end
