# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# Sanitize MAC addresses
#
# Many logs contain MAC addresses, but they can arrive in several different
# formats, such as colon-delimited (00:11:22:aa:bb:cc), hyphen-delimited, Cisco
# format (aabb.ccdd.1122), or just plain hex (001122334455). They can also be
# uppercase, lowercase or mixed. This is especially problematic in logs such as
# from a RADIUS server where clients are not all under local control and can
# contain many different formats. This filter makes it easy to convert MAC
# addresses into the same pattern to make searching easier.
#
# Examples:
#
#     # Create new field "client_mac_sanitized" with copy of "client_mac" field
#     # in lowercase colon-delimited format.
#     filter {
#       sanitize_mac {
#         match => { "client_mac" => "client_mac_sanitized" }
#         separator => ":"
#         fixcase => "lower"
#       } 
#     } 
#
#    # Replace "client_mac" and "server_mac" fields with versions in uppercase
#    # Cisco format.
#     filter {
#       sanitize_mac {
#         match => { "client_mac" => "client_mac"
#                    "server_mac" => "server_mac" }
#         separator => "."
#         fixcase => "upper"
#       } 
#     } 

class LogStash::Filters::SanitizeMac < LogStash::Filters::Base
  config_name "sanitize_mac"
  milestone 1

  # Hash of fields to process; key is input field, value is output field.
  # Input and output field may be the same, in which case the value of the field
  # is replaced assuming the data looks like a MAC address and can be sanitized.
  config :match, :validate => :hash, :default => {}

  # MAC address separator for rewritten address; can be any of
  #  ":", "-", "." or "".
  config :separator, :validate => :string, :default => ":"

  # Fix case of MAC address. "lower", "upper" or "" to just leave it alone.
  config :fixcase, :validate => :string, :default => ""

  public
  def register
    if [":", "-", ".", ""].index(@separator).nil?
      @logger.error("Invalid sanitize_mac configuration. 'separator' must be one of ':', '-', '.' or blank.")
      raise "Bad configuration, aborting."
    end
    
    if ["lower", "upper", ""].index(@fixcase).nil?
      @logger.error("Invalid sanitize_mac configuration. 'fixcase' must be one of 'lower', 'upper', blank.")
      raise "Bad configuration, aborting."
    end

    if @match.nil?
      @logger.error("Invalid sanitize_mac configuration. 'match' must be defined.")
      raise "Bad configuration, aborting."
    end
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    @match.keys.each do |field|
      next if event[field].nil?

      # Work out what format the incoming MAC address is in. As well as
      # well-formed addresses, this has to cope with things like missing
      # leading-zeroes, and ensuring that something using mixed delimiters
      # does not parse.

      # looks colon-delimited?
      if event[field] =~ /^(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$/i
        octets = event[field].split(":")
        mac = octets.map { |o| (o.length == 1 ? "0" + o : o) }.join

      # looks hyphen-delimited?
      elsif event[field] =~ /^(?:[0-9a-f]{1,2}-){5}[0-9a-f]{1,2}$/i
        octets = event[field].split("-")
        mac = octets.map { |o| (o.length == 1 ? "0" + o : o) }.join

      # looks cisco dot-delimited?
      elsif event[field] =~ /^[0-9a-f]{1,4}\.[0-9a-f]{1,4}\.[0-9a-f]{1,4}$/i
        words = event[field].split(".")
        mac = words.map { |o| (o.length < 4 ? ("000" + o)[-4..-1] : o) }.join

      # last try; could just be 12-digit hex?
      elsif event[field] =~ /^[0-9a-f]{12}$/i
        mac = event[field]

      # give up, it doesn't look like a MAC address
      else
        next
      end

      # verify what we're left with really does look like a mac address
      next unless mac.length == 12

      # split up into octets (or 16 bits for cisco format)
      if separator == "."
        octets = mac.unpack("A4A4A4")
      else
        octets = mac.unpack("A2A2A2A2A2A2")
      end

      # push the updated value back
      new_field = @match[field]
      case @fixcase
        when "lower" then event[new_field] = octets.join(separator).downcase
        when "upper" then event[new_field] = octets.join(separator).upcase
        else event[new_field] = octets.join(separator)
      end

    end

    filter_matched(event)
  end # def filter
end # class LogStash::Filters::SanitizeMac

