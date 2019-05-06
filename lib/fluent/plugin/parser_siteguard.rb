#
# Copyright 2019- TODO: Write your name
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "fluent/plugin/parser"

module Fluent
  module Plugin
    class SiteguardParser < Fluent::Plugin::Parser
      Fluent::Plugin.register_parser("siteguard_parser", self)

      DETECT = /^(?<time>[\d.]+)\s+(?<connect_time>\d+)\s(?<host_ip>[\S.]+)\sTCP\_MISS\/000\s(?<file_size>\d+)\s(?<method>[A-Z]+)\s(?<url>\S+)\s-\sDIRECT\/(?<hierarchy_code>[\d.]+)\s(?<content_type>\S+)\sDETECT-STAT:WAF:(?<detect_name>[^:]+)::(?<detect_str>[^:]*):(?<all_detect_str>[^:]*):\sACTION:(?<action>[^:]+):\sJUDGE:(?<judge>[^:]+):(?<monitored>[01]):\sSEARCH-KEY:(?<serch_key>[\d.]+):$/
      FORM = /^(?<time>[\d.]+)\s+(?<process_id>\d+)\s(?<host_ip>[\S.]+)\s(?<url>\S+)\s(?<type>\S+):\s(?<param>\S+)\sSEARCH-KEY:(?<serch_key>[\d.]+):$/
      TIME_FORMAT = "%s"

      config_param :message_format, :enum, list: [:detect, :form], default: :detect

      def initialize
        super
        @mutex = Mutex.new
      end

      def configure(conf)
        super
        @time_parser = time_parser_create(format: TIME_FORMAT)
        @regexp = case @message_format
                  when :detect
                    DETECT
                  when :form
                    FORM
                  end
      end

      def parse(text)
        m = @regexp.match(text)
        unless m
          yield nil, nil
          return
        end

        time = nil
        record = {}

        m.names.each { |name|
          if value = m[name]
            case name
            when 'time'
              time = @mutex.synchronize { @time_parser.parse(m['time']) }
              record[name] = m[name] if @keep_time_key
            else
              record[name] = m[name]
            end
          end
        }
        yield time, record
      end
    end
  end
end
