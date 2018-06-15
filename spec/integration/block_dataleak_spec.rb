require "spec_helper"

describe "Integration Specs" do

  before(:all) do
    `build/nginx/sbin/nginx`
    sleep 1
  end

  after(:all) do
    `build/nginx/sbin/nginx -s stop`
  end
  
  describe "Data Leakage" do
    describe "GET" do
      it "allows a request to a file in a dir" do
        http = Curl.get("http://127.0.0.1:8888/somedir/one")
        expect(http.response_code).to eq(200)
      end

      it "blocks a dir-listing dataleakage event" do
        http = Curl.get("http://127.0.0.1:8888/somedir/")
        expect(http.response_code).to eq(403)
      end
    end
  end
end
