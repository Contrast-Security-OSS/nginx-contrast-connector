require "spec_helper"

describe "Integration Specs" do
  
  describe "IP Whitelist" do
    it "allows from 124.124.124.124 (if setup in Teamserver)" do
      http = Curl.get("http://127.0.0.1:8888?attack=%27%20or%201%3D1%3B%20--") do |curl|
        curl.headers['User-Agent'] = "Bob's House of Software"
        curl.headers['X-Forwarded-For'] = "124.124.124.124"
      end
      expect(http.response_code).to eq(200)
    end
  end
end
