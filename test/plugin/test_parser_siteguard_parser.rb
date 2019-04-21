require "helper"
require "fluent/plugin/parser_siteguard_parser.rb"

class SiteguardParserParserTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
    @parser = Fluent::Test::Driver::Parser.new(Fluent::Plugin::SiteguardParserParser)
  end

  def test_parse_detect
    text = '1555835923.548072      0 172.28.0.4 TCP_MISS/000 0 GET http://siteguard/WAF-TEST-SIGNATURE/ - DIRECT/172.28.0.3 - DETECT-STAT:WAF:RULE_SIG/PART_PATH//OFFICIAL/94001001/url-waf-test-1::/WAF-TEST-SIGNATURE:: ACTION:BLOCK: JUDGE:BLOCK:0: SEARCH-KEY:1555835923.548072.87337:'
    @parser.configure({ 'message_format' => 'detect' })
    @parser.instance.parse(text) { |time, record|
      assert_equal(event_time('2019-04-21T17:38:43 +0900', format: '%Y-%m-%dT%H:%M:%S %z'), time)
      assert_equal '0', record['connect_time']
      assert_equal '172.28.0.4', record['host_ip']
      assert_equal '0', record['file_size']
      assert_equal 'GET', record['method']
      assert_equal 'http://siteguard/WAF-TEST-SIGNATURE/', record['url']
      assert_equal '172.28.0.3', record['hierarchy_code']
      assert_equal '-', record['content_type']
      assert_equal 'RULE_SIG/PART_PATH//OFFICIAL/94001001/url-waf-test-1', record['detect_name']
      assert_equal '/WAF-TEST-SIGNATURE', record['detect_str']
      assert_equal '', record['all_detect_str']
      assert_equal 'BLOCK', record['action']
      assert_equal 'BLOCK', record['judge']
      assert_equal '0', record['monitored']
      assert_equal '1555835923.548072.87337', record['serch_key']
    }
  end

  def test_parse_with_keep_time_key
    text = '1555835923.548072      0 172.28.0.4 TCP_MISS/000 0 GET http://siteguard/WAF-TEST-SIGNATURE/ - DIRECT/172.28.0.3 - DETECT-STAT:WAF:RULE_SIG/PART_PATH//OFFICIAL/94001001/url-waf-test-1::/WAF-TEST-SIGNATURE:: ACTION:BLOCK: JUDGE:BLOCK:0: SEARCH-KEY:1555835923.548072.87337:'
    @parser.configure({
      'keep_time_key' => 'true',
      'message_format' => 'detect'
    })
    @parser.instance.parse(text) { |time, record|
      assert_equal '1555835923.548072', record['time']
    }
  end

  def test_parse_form
    text = '1485224392.424000 0 192.168.1.1 http://xxxxxxxxxx/sig_test.php REQBODY/multipart/form-data: hoge=%3Cscript%3E SEARCH-KEY:1485224392.424000.2:'
    @parser.configure({
      'message_format' => 'form'
    })
    @parser.instance.parse(text) { |time, record|
      assert_equal(event_time('2017-01-24T11:19:52 +0900', format: '%Y-%m-%dT%H:%M:%S %z'), time)
      assert_equal '0', record['process_id']
      assert_equal '192.168.1.1', record['host_ip']
      assert_equal 'http://xxxxxxxxxx/sig_test.php', record['url']
      assert_equal 'REQBODY/multipart/form-data', record['type']
      assert_equal 'hoge=%3Cscript%3E', record['param']
      assert_equal '1485224392.424000.2', record['serch_key']
    }
  end
end
