require 'spec_helper'

describe "Integration Specs" do
  
  before(:all) do
    `build/nginx/sbin/nginx`
    sleep 1
  end

  after(:all) do
    `build/nginx/sbin/nginx -s stop`
  end

  describe "VirtualPatch" do
    it "can block a request with a matching parameter value (if defined in Teamserver)" do
      http = Curl.get("http://127.0.0.1:8888", { virtual_patch: true }) do |curl|
        curl.headers['User-Agent'] = "Mozilla"
      end
      expect(http.response_code).to eq(403)
    end

    it "can allow a request with a non-matching parameter value (if defined in Teamserver)" do
      http = Curl.get("http://127.0.0.1:8888", { virtual_patch: false }) do |curl|
        curl.headers['User-Agent'] = "Mozilla"
      end
      expect(http.response_code).to eq(200)
    end

  end
end
