require "spec_helper"

describe "Integration Specs" do

  describe "IP Blacklist" do
    it "blocks from 123.123.123.123 (if setup in Teamserver)" do
      http = Curl.get("http://127.0.0.1:8888") do |curl|
        curl.headers['User-Agent'] = "Bob's House of Software"
        curl.headers['X-Forwarded-For'] = "123.123.123.123"
      end
      expect(http.response_code).to eq(403)
    end

    it "blocked from 20.20.20.0/24 ip block (if setup in Teamserver)" do
      http = Curl.get("http://127.0.0.1:8888") do |curl|
        curl.headers['User-Agent'] = "Bob's House of Software"
        curl.headers['X-Forwarded-For'] = "20.20.20.0"
      end
      expect(http.response_code).to eq(403)

    end
  end
end
