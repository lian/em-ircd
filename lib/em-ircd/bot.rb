require 'eventmachine'

module IRC
  class Bot < EM::Connection # simple bot class
    attr_reader :nick, :channels
    attr_reader :on_privmsg, :on_join

    def initialize(nick, channels)
      @nick, @channels = nick, channels

      @on_privmsg = EM::Channel.new
      @on_join    = EM::Channel.new
    end

    MSG_LOGIN = "NICK %s\nUSER %s %s 0.0.0.0 :%s\nMODE %s +i\n"
    MSG_JOIN  = "JOIN %s\nMODE %s\nWHO %s\n"

    def post_init
      init_buffer
      send_data(MSG_LOGIN % ([@nick]*5))
      @channels.each{|i| join_channel(i) }
    end

    def join_channel(channel)
      send_data(MSG_JOIN % [channel, channel, channel])
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
      @buffer += data; @process_buffer.call
    end

    def receive_line(line)
      #p [Time.now.tv_sec, line]
      case line
        when /^\:(.+) PRIVMSG (.+) :(.+)$/
          @on_privmsg << [$1, $2, $3]
        when /^\:(.+) JOIN (.+)$/
          @on_join << [$1, $2]
      end
    end

    def unbind
      puts "lost irc connection"
    end

    def self.connect(host, port, *args)
      EM.connect(host, port, self, *args)
    end
  end
end


if __FILE__ == $0
  EM.run do

    bot = IRC::Bot.connect('127.0.0.1', 6667, 'em-bot', ['#welcome', '#eventmachine'])
    bot.on_privmsg.subscribe{|from,channel,msg|
      p ['privmsg callback', from,channel,msg]
    }

  end
end
