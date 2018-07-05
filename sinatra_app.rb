require 'thin'
require 'sinatra'
require 'json'
require 'ox'

get '/simple' do
  erb :simple
end

def safe_string body
  if body.respond_to?(:string)
    body.string
  else
    body.to_s
  end
end

post '/json' do
  @obj = JSON.parse(safe_string(request.body))
  erb :json
end

post '/xml' do
  @obj = Ox.parse(safe_string(request.body))
  erb :xml
end

post '/text' do
  @text = safe_string(request.body)
  erb :text
end

post '/login' do
  puts "REQUEST=#{ request.params }"
  if request.params['user'] == 'alice' && request.params['pass'] == '$ecur3'
    redirect '/sinatra/simple'
  else
    status 401
    body 'that is an incorrect password'
  end
end

__END__

@@ simple
  <h1>Received the following params</h1>
  <% params.each do |k,v| %>
    <div><b><%= k %></b>: <%= v %></div> 
  <% end %>


@@ json
  <h1>Received the following JSON</h1>
  <div>
    <%= @obj.inspect %>
  </div>


@@ xml
  <h1>Received the following XML</h1>
  <div>
    <%= @obj.inspect %>
  </div>


@@ text
  <h1>Received the following TEXT</h1>
  <p>
    <%= @text %>
  </p>


@@ layout
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="utf-8">
      <title>Simple Sinatra App</title>
    </head>
    <body><%= yield %></body>
  </html>
