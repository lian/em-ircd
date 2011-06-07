require 'eventmachine'

module IRC
  class Bot < EM::Connection # simple bot class
    def self.connect(host, port, *args, &blk)
      EM.connect(host, port, self, [host, port], *args, blk)
    end


    attr_reader :nick, :channels
    attr_reader :on_privmsg, :on_join, :on_unkown

    def initialize(sockaddr, nick, channels, cfg={}, rebind_cb=nil, &rebind_blk)
      @_sockaddr, @rebind_cb = sockaddr, (rebind_cb || rebind_blk)

      @nick, @channels = nick, channels
      @cfg = cfg

      @on_privmsg = EM::Channel.new
      @on_join    = EM::Channel.new
      @on_unkown  = EM::Channel.new

      @rebind_cb && @rebind_cb.call( self )
    end

    MSG_LOGIN = "NICK %s\nUSER %s %s 0.0.0.0 :%s\nMODE %s +i\n"
    MSG_JOIN  = "JOIN %s\nMODE %s\n" #WHO %s\n"
    MSG_AUTH  = "MODE %s +i\n PRIVMSG %s IDENTIFY %s\n"


    def post_init
      if @cfg['ssl']
        start_tls :verify_peer => true
      else
        @handshake_completed = true
        post_init_plain
      end
    rescue Exception => ex
      p [ex.message, ex.backtrace]
    end

    def ssl_verify_peer(cert)
      true
    end

    def post_init_plain
      init_buffer
      login!
      @channels[0..0].each{|i| join_channel(i) }
    end

    def ssl_handshake_completed
      @handshake_completed = true
      post_init_plain
    end


    def login!
      send_data(MSG_LOGIN % ([@nick]*5))
      send_data(MSG_AUTH % [@nick, @nick, @cfg['pw']]) if @cfg['pw']
    end


    def join_channel(channel)
      send_data(MSG_JOIN % [channel, channel]) #, channel])
    end

    def privmsg(dst, msg)
      send_data("PRIVMSG #{dst} :#{msg}\n")
    end

    def init_buffer
      @buffer = ""
      @process_buffer = Proc.new{  # handles receive_line
        if @buffer.include?("\n")
          receive_line( @buffer.slice!(0, @buffer.index("\n")+1).chomp )
          EM.next_tick(&@process_buffer) if @buffer.include?("\n")
        end
      }
    end

    def receive_data(data)
      (@buffer += data; @process_buffer.call) if @handshake_completed
    end

    def receive_line(line)
      case line

        when /^\:(.+) PRIVMSG (#?\S+) :(.+)$/
          @on_privmsg << [$1, $2, $3]

        when /^\:(.+) JOIN (.+)$/
          @on_join << [$1, $2]

        when /^PING \:(.+)$/
          send_data("PONG :%s\n" % [$1])

        else
          @on_unkown << [Time.now.tv_sec, line]

      end
    end

    def unbind
      puts "unbind IRC::Bot Connection: #{@_sockaddr.inspect}"
      EM.add_timer(45){ p :rebind; rebind! }
    end

    def rebind!
      @rebind_cb && EM.connect(*@_sockaddr, self.class, @_sockaddr, @nick, @channels, @cfg, @rebind_cb)
    end

    def list_channels
      @channels.each{|i| send_data('NAMES %s\n' % [i]) }
    end
  end
end



if __FILE__ == $0

  # simple bot example
  EM.run do

    nick     = 'em-bot-' + Process.pid.to_s
    channels = ['#testing']
    config   = {}  # or: 'ssl' => true


    IRC::Bot.connect('127.0.0.1', 6667, nick, channels, config) do |bot|

      bot.on_privmsg.subscribe{|from,channel,msg|
        p ['privmsg', from, channel, msg]

        begin
        case msg

          when /(.+): help$/
            if $1 == bot.nick
              bot.privmsg(channel, "noch keine hilfe..")
            end

          when /(.+): part!$/
            if $1 == bot.nick
              bot.privmsg(channel, "bye bye.")
              EM.add_timer(2){ EM.stop }
            end

        end
        rescue Exception => ex
          p [ex.message, ex.backtrace]
        end
      }

      bot.on_unkown.subscribe{|time,line|
        p ['raw line', time, line]
      }

    end

  end
end
