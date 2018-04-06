require "spec_helper"

describe "Integration Specs" do

  before(:all) do
    `build/nginx/sbin/nginx`
    sleep 1
  end

  after(:all) do
    `build/nginx/sbin/nginx -s stop`
  end
  
    describe "BotBlocker" do
      it "allows a request without a user agent" do
        http = Curl.get("http://127.0.0.1:8888") do |curl|
          curl.headers['User-Agent'] = ""
        end
        expect(http.response_code).to eq(200)
      end
      it "allows a request with a user agent" do
        http = Curl.get("http://127.0.0.1:8888") do |curl|
          curl.headers['User-Agent'] = "Mozilla"
        end
        expect(http.response_code).to eq(200)
      end
      it "blocks a request with a bad user agent" do
        http = Curl.get("http://127.0.0.1:8888") do |curl|
          curl.headers['User-Agent'] = "Go!Zilla"
        end
        expect(http.response_code).to eq(403)
      end
    end
end
