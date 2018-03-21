require "rake"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:integration) do |t|
  t.pattern ="spec/**/*_spec.rb"
end

namespace :nginx do
  desc "Starts NGINX"
  task :start do
    `build/nginx/sbin/nginx`
    sleep 1
  end

  desc "Stops NGINX"
  task :stop do
    `build/nginx/sbin/nginx -s stop`
  end

  desc "Recompiles NGINX"
  task :compile do
    sh "script/compile"
  end
end

namespace :sinatra do
  desc "Starts Sinatra"
  task :start do
    `nohup ruby sinatra_app.rb > build/nginx/logs/sinatra.log 2>&1 &`
    puts `echo $!`
    sleep 1
  end
end

desc "Bootstraps the local development environment"
task :bootstrap do
  unless Dir.exists?("build") and Dir.exists?("vendor")
    sh "script/bootstrap"
  end
end

desc "Run the integration tests"
task default: [ :bootstrap, :integration ]


