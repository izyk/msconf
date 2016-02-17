#!/bin/sh
# Version info - $Id: iptbl.sh,v 1.4 2016-02-12 16:59:09+03 ilia Exp ilia $

IPTABLES=/sbin/iptables
SYSCTL=/sbin/sysctl

# ACTIVE ZONES
ZPATH=$(pwd)/zones
ZONES="eth00 eth01 lbr0"

zone_init () {
# IPV4 ZONE

indev=false
in4ip=no_address
masq=no		# MASQUERADE packets to this network
trust=no	# ACCEPT all packets from this network
forward=no	# FORWARD all packets from this network

# INPUT
I4U=""	# UDP
I4T=""	# TCP

# SECURITY ATTENTION!
# OPEN TWO PORTS ON INTERFACE (sport,dport) maybe vulnerability!!! Don't use on external.
# LOCAL REDIRECTION - example "source,destination 1015,2012" space separator
I4UR="" # UDP
I4TR=""	# TCP

# SECURITY ATTENTION!
# maybe vulnerability without "net.ipv4.conf.all.rp_filter = 1"
# without above can OPEN TWO PORTS ON INTERFACE (sport,dport).
# FORWARDING - example "sport,dstip,dport 10080,192.168.40.40,20008" space separator
F4U=""	# UDP
F4T=""	# TCP

# IPV4 ZONE END
}

get_param () {
  eval GET_PARAM=\$$1
}
parse_comma () {
  PARSE_COMMA=$(echo $1 | tr "," ' ')
}

build_local_redirect () {
  # echo $1 zone
  # echo $2 proto
  # echo $3 sport
  # echo $4 dport
  $IPTABLES -t nat    -A ${1}_nat   -p $2 --dport $3 -j REDIRECT --to-ports $4
  $IPTABLES -t filter -A ${1}_input -p $2 --dport $4 -j ACCEPT
}

build_forward_rule () {
  # echo $1 zone
  # echo $2 proto
  # echo $3 sport
  # echo $4 dstip
  # echo $5 dport
  $IPTABLES -t nat    -A ${1}_nat     -p $2       --dport $3 -j DNAT --to $4:$5
  $IPTABLES -t filter -A ${1}_forward -p $2 -d $4 --dport $5 -j ACCEPT
}

# ( "ZONE" "NAME OF PARAM - ex: F4U" "PROTO" )
parse_4forward () {
  get_param $2
  for fpar in $GET_PARAM
  do
    parse_comma $fpar
    build_forward_rule $1 $3 $PARSE_COMMA
  done
}

# ( "ZONE" "NAME OF PARAM - ex: F4UR" "PROTO" )
local_4redirect () {
  get_param $2
  for fpar in $GET_PARAM
  do
    parse_comma $fpar
    build_local_redirect $1 $3 $PARSE_COMMA
  done
}

# ( "ZONE" "PORTS" "PROTO" )
in_ports () {
  if [ x"$2" != x"" ]; then
    $IPTABLES -t filter -A ${1}_input -p $3 -m multiport --dports $2 -j ACCEPT
  fi
}

load_zones () {
  for zone in $ZONES
  do
    zone_init
    . $ZPATH/$zone
    $IPTABLES -t nat    -N ${zone}_nat
    $IPTABLES -t filter -N ${zone}_input
    $IPTABLES -t filter -N ${zone}_forward
    $IPTABLES -t nat    -A PREROUTING -i $indev -d $in4ip -j ${zone}_nat
    $IPTABLES -t filter -A INPUT      -i $indev -d $in4ip -j ${zone}_input
    $IPTABLES -t filter -A FORWARD    -i $indev -j ${zone}_forward # no $in4ip maybe vulnerability without "net.ipv4.conf.all.rp_filter = 1"
    if [ $masq == 'yes' ]; then
      $IPTABLES -t nat    -A POSTROUTING -o $indev -m addrtype ! --src-type LOCAL  -j MASQUERADE
    fi
    if [ $trust == 'yes' ]; then
      $IPTABLES -t filter -A INPUT   -i $indev -j ACCEPT
    fi
    if [ $forward == 'yes' ]; then
      $IPTABLES -t filter -A FORWARD -i $indev -j ACCEPT
    fi
    in_ports $zone "$I4U" udp
    in_ports $zone "$I4T" tcp
    local_4redirect $zone I4UR udp
    local_4redirect $zone I4TR tcp
    parse_4forward $zone F4U udp
    parse_4forward $zone F4T tcp
  done
}

create_rules () {
  $IPTABLES -t filter -N CHECK-NEW-TCP
  $IPTABLES -t filter -A CHECK-NEW-TCP -p tcp --syn -j RETURN
  $IPTABLES -t filter -A CHECK-NEW-TCP -p tcp ! --tcp-flags SYN,ACK,FIN,RST SYN,ACK -j DROP
  $IPTABLES -t filter -A CHECK-NEW-TCP -p tcp -j REJECT --reject-with tcp-reset

  $IPTABLES -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IPTABLES -t filter -A INPUT -m state ! --state NEW -j DROP
  $IPTABLES -t filter -A INPUT -p tcp -j CHECK-NEW-TCP
  $IPTABLES -t filter -A INPUT -p icmp -j ACCEPT
  $IPTABLES -t filter -A INPUT -i lo -j ACCEPT

  $IPTABLES -t filter -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IPTABLES -t filter -A FORWARD -m state ! --state NEW -j DROP
  $IPTABLES -t filter -A FORWARD -p tcp -j CHECK-NEW-TCP

  load_zones

  $IPTABLES -t filter -A INPUT -j REJECT --reject-with icmp-host-prohibited
  $IPTABLES -t filter -A FORWARD -j REJECT --reject-with icmp-host-prohibited
}

usage() {
    echo "Usage: $(basename $0) {start|stop} [test]" 1>&2
    exit $1
}

stop() {
  $IPTABLES -F
  $IPTABLES -t raw -F
  $IPTABLES -t nat -F
  $IPTABLES -t mangle -F
  $IPTABLES -Z
  $IPTABLES -t raw -Z
  $IPTABLES -t nat -Z
  $IPTABLES -t mangle -Z
  $IPTABLES -X
  $IPTABLES -t raw -X
  $IPTABLES -t nat -X
  $IPTABLES -t mangle -X
  $IPTABLES -P INPUT ACCEPT
  $IPTABLES -P OUTPUT ACCEPT
  $IPTABLES -P FORWARD ACCEPT
}

start() {
  create_rules
}

if [ ! -x $IPTABLES ]
then
  echo "$IPTABLES does not exist." 1>&2
  exit 2
fi
if [ ! -x $SYSCTL ]
then
  echo "$SYSCTL does not exist." 1>&2
  exit 3
fi

if [ $# -gt 1 ]
then
  if [ $# -eq 2 -a $2 = 'test' ]
  then
    IPTABLES="echo iptables"
    SYSCTL="echo sysctl"
  else
    usage 1
  fi
fi

case "$1" in
    start)
	stop
	start
	RETVAL=$?
	;;
    stop)
	stop
	RETVAL=$?
	;;
    *)
	usage 1
	;;
esac

exit $RETVAL
