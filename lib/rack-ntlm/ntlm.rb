require 'net/ldap'
require 'net/ntlm'

module Rack
  class Ntlm

    def initialize(app, config = {})
      default_condition = lambda do |env| true end
      @app = app
      @config = {
        :uri_pattern => /\//,
        :condition => default_condition
      }.merge(config)
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

        # XXX Implement actual authentication
        # The challenge-response pair needs to be verified
        if message.type == 1
          type2 = Net::NTLM::Message::Type2.new
          return [401, {"WWW-Authenticate" => "NTLM " + type2.encode64}, []]
        end

        if message.type == 3 && env['PATH_INFO'] =~ @config[:uri_pattern]
          user = Net::NTLM::decode_utf16le(message.user)
          env['REMOTE_USER'] = user
        end
      end

      @app.call(env)
    end
  end
end
