require "spec_helper"

describe "Integration Specs" do
  
  describe "SQLi" do
    it "allows a request without an attack vector" do
      http = Curl.get("http://127.0.0.1:8888") do |http|
        # NOOP
      end

      expect(http.response_code).to eq(200)
    end

    it "blocks a request with an attack venctor" do
      http = Curl.get("http://127.0.0.1:8888?attack=%27%20or%201%3D1%3B%20--") do |http|
        # NOOP
      end

      expect(http.response_code).to eq(403)
    end
  end
end
