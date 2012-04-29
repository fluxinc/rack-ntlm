require 'net/ldap'
require 'net/ntlm'

module Rack
  class Ntlm

    def initialize(app, config = {})
      default_condition = lambda do |env| true end
      @app = app
      @config = {
        :uri_pattern => /\//,
        :port => 389,
        :search_filter => "(sAMAccountName=%1)",
        :condition => default_condition
      }.merge(config)
    end

    def auth(user)
      ldap = Net::LDAP.new
      ldap.host = @config[:host]
      ldap.port = @config[:port]
      ldap.base = @config[:base]
      ldap.auth @config[:auth][:username], @config[:auth][:password] \
        if @config[:auth]
      !ldap.search(:filter => @config[:search_filter].gsub("%1", user)).empty?
    rescue => e
      false
    end

    def call(env)
      if env['HTTP_AUTHORIZATION'].blank? &&
         env['PATH_INFO'] =~ @config[:uri_pattern] &&
         @config[:condition].call(env)
        return [401, {'WWW-Authenticate' => "NTLM"}, []]
      end

      if /^(NTLM|Negotiate) (.+)/ =~ env["HTTP_AUTHORIZATION"]
        plain = Base64::decode64($2)
        message = Net::NTLM::Message.decode64($2)

        if message.type == 1
          type2 = Net::NTLM::Message::Type2.new
          return [401, {"WWW-Authenticate" => "NTLM " + type2.encode64}, []]
        end

        if message.type == 3 && env['PATH_INFO'] =~ @config[:uri_pattern]
          user = Net::NTLM::decode_utf16le(message.user)
          if auth(user)
            env['REMOTE_USER'] = user
          else
            return [401, {}, ["You are not authorized to see this page"]]
          end
        end
      end

      @app.call(env)
    end
  end
end
