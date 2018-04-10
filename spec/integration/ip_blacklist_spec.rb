require "spec_helper"

describe "Integration Specs" do

  before(:all) do
    `build/nginx/sbin/nginx`
    sleep 1
  end

  after(:all) do
    `build/nginx/sbin/nginx -s stop`
  end
  
  describe "IP Blacklist" do
    it "blocks from 123.123.123.123 (if setup in Teamserver)" do
      http = Curl.get("http://127.0.0.1:8888") do |curl|
        curl.headers['User-Agent'] = "Bob's House of Software"
        curl.headers['X-Forwarded-For'] = "123.123.123.123"
      end
      expect(http.response_code).to eq(403)
    end
  end
end
