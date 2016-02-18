#!/bin/sh
# Version info - $Id: iptbl.sh,v 1.4 2016-02-12 16:59:09+03 ilia Exp ilia $

IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables

# ACTIVE ZONES
ZPATH=$(pwd)/zones
ZONES="eth00 eth01 lbr0"

zone_init() {
# IPV4 IPV6 ZONE

indev=false
in4ip=no_address
in6net=no_address
masq=no		# MASQUERADE packets to this network only IPV4
trust=no	# ACCEPT all packets from this network
forward=no	# FORWARD all packets from this network

# INPUT
INU=""	# UDP
INT=""	# TCP

# SECURITY ATTENTION!
# OPEN WIDE TWO PORTS sport and dport - maybe vulnerability!!! Don't use on external.
# LOCAL REDIRECTION - example "source,destination 1015,2012" space separator
I4UR="" # UDP
I4TR=""	# TCP

# SECURITY ATTENTION!
# maybe vulnerability without "net.ipv4.conf.all.rp_filter = 1"
# without above can OPEN TWO PORTS ON INTERFACE (sport,dport).
# FORWARDING - example "sport,dstip,dport 10080,192.168.40.40,20008" space separator
F4U=""	# UDP
F4T=""	# TCP

# IPV4 IPV6 ZONE END
}

get_param() {
  eval GET_PARAM=\$$1
}
parse_comma() {
  PARSE_COMMA=$(echo $1 | tr "," ' ')
}

build_local_redirect() {
  # echo $1 zone
  # echo $2 proto
  # echo $3 sport
  # echo $4 dport
  $IPTABLES -t nat    -A NAT_${1}   -p $2 --dport $3 -j REDIRECT --to-ports $4
  $IPTABLES -t filter -A INPUT_${1} -p $2 --dport $4 -j ACCEPT
}

build_forward_rule() {
  # echo $1 zone
  # echo $2 proto
  # echo $3 sport
  # echo $4 dstip
  # echo $5 dport
  $IPTABLES -t nat    -A NAT_${1}     -p $2       --dport $3 -j DNAT --to $4:$5
  $IPTABLES -t filter -A FORWARD_${1} -p $2 -d $4 --dport $5 -j ACCEPT
}

# ( "ZONE" "NAME OF PARAM - ex: F4U" "PROTO" )
parse_4forward() {
  get_param $2
  for fpar in $GET_PARAM
  do
    parse_comma $fpar
    build_forward_rule $1 $3 $PARSE_COMMA
  done
}

# ( "ZONE" "NAME OF PARAM - ex: F4UR" "PROTO" )
local_4redirect() {
  get_param $2
  for fpar in $GET_PARAM
  do
    parse_comma $fpar
    build_local_redirect $1 $3 $PARSE_COMMA
  done
}

# ( "ZONE" "PORTS" "PROTO" )
in_ports() {
  if [ x"$2" != x"" ]; then
    $IPTABLES -t filter -A INPUT_${1} -p $3 -m multiport --dports $2 -j ACCEPT
    $IP6TABLES -t filter -A INPUT_${1} -p $3 -m multiport --dports $2 -j ACCEPT
  fi
}

load_zones() {
  for zone in $ZONES
  do
    zone_init
    . $ZPATH/$zone

    if [ $trust == 'yes' ]; then
      $IPTABLES -t filter -A INPUT   -i $indev -j ACCEPT
      $IP6TABLES -t filter -A INPUT   -i $indev -j ACCEPT
    fi
    if [ $forward == 'yes' ]; then
      $IPTABLES -t filter -A FORWARD -i $indev -j ACCEPT
      $IP6TABLES -t filter -A FORWARD -i $indev -j ACCEPT
    fi

    $IPTABLES -t nat    -N NAT_${zone}
    $IPTABLES -t filter -N INPUT_${zone}
    $IPTABLES -t filter -N FORWARD_${zone}
    $IPTABLES -t nat    -A PREROUTING -i $indev -d $in4ip -j NAT_${zone}
    $IPTABLES -t filter -A INPUT      -i $indev -d $in4ip -j INPUT_${zone}
    $IPTABLES -t filter -A FORWARD    -i $indev -j FORWARD_${zone} # no $in4ip maybe vulnerability without "net.ipv4.conf.all.rp_filter = 1"
    if [ $masq == 'yes' ]; then
      $IPTABLES -t nat    -A POSTROUTING -o $indev -m addrtype ! --src-type LOCAL  -j MASQUERADE
    fi

    $IP6TABLES -t filter -N INPUT_${zone}
    $IP6TABLES -t filter -N FORWARD_${zone}
    $IP6TABLES -t filter -A INPUT      -i $indev -d $in6net -j INPUT_${zone}
    $IP6TABLES -t filter -A FORWARD    -i $indev -d $in6net -j FORWARD_${zone}

    in_ports $zone "$INU" udp
    in_ports $zone "$INT" tcp

    local_4redirect $zone I4UR udp
    local_4redirect $zone I4TR tcp
    parse_4forward $zone F4U udp
    parse_4forward $zone F4T tcp
  done
}

# ( $IPTABLES )
create_default(){
  local iptbl="$1"
  $iptbl -t filter -N CHECK-NEW-TCP
  $iptbl -t filter -A CHECK-NEW-TCP -p tcp --syn -j RETURN
  $iptbl -t filter -A CHECK-NEW-TCP -p tcp ! --tcp-flags SYN,ACK,FIN,RST SYN,ACK -j DROP
  $iptbl -t filter -A CHECK-NEW-TCP -p tcp -j REJECT --reject-with tcp-reset

  $iptbl -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  $iptbl -t filter -A INPUT -m state ! --state NEW -j DROP
  $iptbl -t filter -A INPUT -p tcp -j CHECK-NEW-TCP
  $iptbl -t filter -A INPUT -i lo -j ACCEPT

  $iptbl -t filter -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  $iptbl -t filter -A FORWARD -m state ! --state NEW -j DROP
  $iptbl -t filter -A FORWARD -p tcp -j CHECK-NEW-TCP
}

create_rules() {
  create_default "$IPTABLES"
  create_default "$IP6TABLES"
    
  $IPTABLES -t filter -A INPUT -p icmp -j ACCEPT
  $IP6TABLES -t filter -A INPUT -p ipv6-icmp -j ACCEPT

  load_zones

  $IPTABLES -t filter -A INPUT -j REJECT --reject-with icmp-host-prohibited
  $IPTABLES -t filter -A FORWARD -j REJECT --reject-with icmp-host-prohibited

  $IP6TABLES -t filter -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
  $IP6TABLES -t filter -A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
}

usage() {
    echo "Usage: $(basename $0) {start|stop} [test]" 1>&2
    exit $1
}

# ( $IPTABLES )
reset_tables() {
  local iptbl="$1"
  $iptbl -F
  $iptbl -t raw -F
  $iptbl -t nat -F
  $iptbl -t mangle -F
  $iptbl -Z
  $iptbl -t raw -Z
  $iptbl -t nat -Z
  $iptbl -t mangle -Z
  $iptbl -X
  $iptbl -t raw -X
  $iptbl -t nat -X
  $iptbl -t mangle -X
  $iptbl -P INPUT ACCEPT
  $iptbl -P OUTPUT ACCEPT
  $iptbl -P FORWARD ACCEPT
}

stop() {
  reset_tables "$IPTABLES"
  reset_tables "$IP6TABLES"
}

start() {
  create_rules
}

if [ ! -x $IPTABLES ]
then
  echo "$IPTABLES does not exist." 1>&2
  exit 2
fi
if [ ! -x $IP6TABLES ]
then
  echo "$IP6TABLES does not exist." 1>&2
  exit 3
fi

if [ $# -gt 1 ]
then
  if [ $# -eq 2 -a $2 = 'test' ]
  then
    IPTABLES="echo iptables"
    IP6TABLES="echo ip6tables"
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
