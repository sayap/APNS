module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  LIVE_GATEWAY = 'gateway.push.apple.com'
  SANDBOX_GATEWAY = 'gateway.sandbox.push.apple.com'

  class Client
    attr_accessor :host, :port, :pem, :pass, :connect_timeout

    def initialize(pem, options={})
      defaults = {
        :pass => nil,
        :host => APNS::LIVE_GATEWAY,
        :port => 2195,
        :connect_timeout => nil,
      }
      options = defaults.merge(options)

      self.pem = pem
      self.pass = options[:pass]
      self.host = options[:host]
      self.port = options[:port]
      self.connect_timeout = options[:connect_timeout]
    end

    def send_notification(device_token, message)
      n = APNS::Notification.new(device_token, message)
      self.send_notifications([n])
    end

    def send_notifications(notifications)
      sock, ssl = self.open_connection

      packed_nofications = self.packed_nofications(notifications)

      notifications.each do |n|
        ssl.write(packed_nofications)
      end

      ssl.close
      sock.close
    end

    def packed_nofications(notifications)
      bytes = ''

      notifications.each do |notification|
        # Each notification frame consists of
        # 1. (e.g. protocol version) 2 (unsigned char [1 byte]) 
        # 2. size of the full frame (unsigend int [4 byte], big endian)
        pn = notification.packaged_notification
        bytes << ([2, pn.bytesize].pack('CN') + pn)
      end

      bytes
    end

    def feedback
      sock, ssl = self.feedback_connection

      apns_feedback = []

      while message = ssl.read(38)
        timestamp, token_size, token = message.unpack('N1n1H*')
        apns_feedback << [Time.at(timestamp), token]
      end

      ssl.close
      sock.close

      return apns_feedback
    end

    protected

    def open_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

      sock         = Socket.tcp(self.host, self.port, opts={connect_timeout: self.connect_timeout})
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end

    def feedback_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

      fhost = self.host.gsub('gateway','feedback')
      puts fhost

      sock         = Socket.tcp(fhost, 2196, opts={connect_timeout: self.connect_timeout})
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end
  end
end
