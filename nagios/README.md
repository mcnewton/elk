Nagios scripts
--------------

check-es-logs is a simple nagios plugin to check that logs being
fed into elasticserch are up-to-date. In other words, that a log
entry has been seen in the last <n> seconds.

Options for the plugin are:

    check-es-logs <host:port> <index> <query> [<period>] [<type>]

 * host:port should be in the form http://hostname[:port]
 * index is the elasticsearch index
 * query should be the query to search, e.g. logsource:hostname
 * period is the number of seconds ago where an entry must be found
 * type is the elasticsearch index _type

The index is automatically appended by -YYYY.MM.DD, the form used
by logstash.

'period' may be omitted, in which case the default is 900 (15
minutes)

'type' may be omitted, in which case the search is done for all
types in the index

Define the plugin in Nagios with something like this:

    define command {
    	command_name	check_es_logs
    	command_line	/usr/local/nagios/plugins/check-es-logs http://localhost $ARG1$ $ARG3$ 900 $ARG2$
    }

The define a service with something like:

    define service {
    	host_name		dhcp-server
    	service_description	elasticsearch DHCP logs
    	check_command		check_es_logs!syslog!dhcp!host:dhcp-server
    	use			generic-service
    }

