require "rspec"
require "rspec/expectations"
require "curb"

RSpec.configure do |config|
  config.before(:suite) do
		puts "Starting NGINX...."
    `build/nginx/sbin/nginx`
    sleep 3
		puts "done"
  end

  config.after(:suite) do
		puts "Stopping NGINX..."
    `build/nginx/sbin/nginx -s stop`
		puts "done"
  end
end
