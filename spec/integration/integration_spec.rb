require "spec_helper"

describe "Integration Specs" do

  before(:all) do
    `nohup ruby sinatra_app.rb > build/nginx/logs/sinatra.log 2>&1 &`
    `build/nginx/sbin/nginx`
    sleep 1
  end

  after(:all) do
    `build/nginx/sbin/nginx -s stop`
    `kill $!`
  end
  
  describe "SQLi" do


    describe "GET" do
      it "allows a request without an attack vector" do
        http = Curl.get("http://127.0.0.1:8888")
        expect(http.response_code).to eq(200)
      end

      it "blocks a request with an attack venctor" do
        http = Curl.get("http://127.0.0.1:8888", { attack: "%27%20or%201%3D1%3B%20--"})
        expect(http.response_code).to eq(403)
      end
    end

    describe "POST" do
      it "allows a request without an attack vector" do
        http = Curl.post("http://127.0.0.1:8888/sinatra/text", { a: 1, b: 2, c: { d: [1, 2, 3] }})
        expect(http.response_code).to eq(200)
      end
    end
  end
end
