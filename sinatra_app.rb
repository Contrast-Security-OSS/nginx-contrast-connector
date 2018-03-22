require 'thin'
require 'sinatra'
require 'json'

get '/simple' do
  erb :simple
end

post '/json' do
  @obj = JSON.parse(request.body)
  erb :json
end

post '/text' do
  @text = request.body.respond_to?(:string) ? 
      request.body.string : 
      request.body.to_s
  erb :text
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
