require "spec_helper"

describe "Integeration Specs" do
  
  describe "Concurrency" do

    describe "GET" do

      it "doesn't crash when a bunch of requests come in simultaneously" do
        responses = []
        threads = []

        100.times do |n|
          thread = Thread.new do
            http = Curl.get("http://127.0.0.1:8888", { thread: "1 OR 2 != 1; --" })
            responses << http.response_code
          end
          threads << thread
        end

        threads.each {|t| t.join }
        count = responses.map {|c| c == 403 ? 1 : 0 }.inject(&:+)
        expect(responses.length).to eq(count)
      end

      it "doesn't crash when a bunch of proxied requests come in simultaneously" do
        responses = []
        threads = []
        100.times do |n|
          thread = Thread.new do
            http = Curl.get("http://127.0.0.1:8888/sinatra/simple", { thread: "1 OR 2 != 1; --" })
            responses << http.response_code
          end
          threads << thread
        end

        threads.each {|t| t.join }
        count = responses.map {|c| c == 403 ? 1 : 0 }.inject(&:+)
        expect(responses.length).to eq(count)
      end
    end
  end
end
