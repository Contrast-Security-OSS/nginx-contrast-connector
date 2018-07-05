require "spec_helper"

describe "Integration Specs" do

  before(:all) do
    `build/nginx/sbin/nginx`
    sleep 1
  end

  after(:all) do
    `build/nginx/sbin/nginx -s stop`
  end
  
  describe "Fail2Ban" do


    describe "POST" do
      it "allows a successful login" do
        10.times do |n|
          http = Curl.post("http://127.0.0.1:8888/sinatra/login", { 
            user: "alice", 
            pass: "$ecur3" 
          })
          puts "RESPONSE CODE = #{ http.response_code }"
        end
      end

      it "allows blocks an unsuccessful login" do
        10.times do |n|
          http = Curl.post("http://127.0.0.1:8888/sinatra/login", { 
            user: "bob", 
            pass: "test" 
          })
          puts "RESPONSE CODE = #{ http.response_code }"
        end
      end
    end
  end
end
