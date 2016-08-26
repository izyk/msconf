#!/bin/sh
# Version info - $Id: iptbl.sh,v 1.1 2016-08-26 19:45:32+03 root Exp root $

IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables

# ZONES
ZPATH=/etc/iptzones
ZONES=$(ls ${ZPATH})

# GLOBAL PARAMETERS
FMASK=0xFF00		# FORWARD MASK
FFLAG=0x8000		# FORWARD FLAG
forward_mark=$FFLAG	# Mark packets as forward max 127.

# Set default (some times useless) values for all parameters.
# In zones files (see above) this should be reinit with correct value.
zone_init() {
indev=false
in4ip=no_address
in6net=no_address
# SNAT (in4ip) packets to this network from this IPV4s. Must be before MASQUARADE
snat=no		# ( x.x.x.x[/mask][,y.y.y.y]... )
masq=no		# MASQUERADE packets to this network only IPV4
trust=no	# ACCEPT all packets from this network
forward=no	# FORWARD all packets from this network

# INPUT
INU=""	# UDP
INT=""	# TCP

# SECURITY ATTENTION!
# OPEN WIDE TWO PORTS sport and dport - maybe vulnerability!!! Don't use on external.
# LOCAL REDIRECTION "input_port,destination_port"
# example "1015,2012 1016,2013" pair separate with space
I4UR="" # UDP
I4TR=""	# TCP

# SECURITY ATTENTION!
# maybe vulnerability without "net.ipv4.conf.all.rp_filter = 1"
# without above can OPEN TWO PORTS ON INTERFACE (sport,dport).
# FORWARDING - example "sport,dstip,dport 10080,192.168.40.40,20008" space separator
F4U=""	# UDP
F4T=""	# TCP

# IPV6 FORWARDING - example "dstip,dport fe00::1,578" space separator
F6T=""	# TCP

} # END the default value init.

get_param() {
  eval GET_PARAM=\$$1
}
parse_comma() {
  PARSE_COMMA=$(echo $1 | tr "," ' ')
}
inc_forward_mark() {
  let forward_mark=forward_mark+0x100
}

build_local_redirect() {
  # echo $1 zone
  # echo $2 proto
  # echo $3 sport
  # echo $4 dport
  inc_forward_mark
  $IPTABLES -t nat -A NAT_${1} -p $2 --dport $3 -j MARK --set-mark $forward_mark
  $IPTABLES -t nat -A NAT_${1} -p $2 -m mark --mark ${forward_mark}/${FMASK} -j REDIRECT --to-ports $4
#  $IPTABLES -t filter -A INPUT_${1} -p $2 --dport $4 -j ACCEPT
}

build_forward_rule() {
  # echo $1 zone
  # echo $2 proto
  # echo $3 sport
  # echo $4 dstip
  # echo $5 dport
  inc_forward_mark
#  $IPTABLES -t mangle -A MARK_${1} -p $2 --dport $3 -j MARK --set-mark $forward_mark
  $IPTABLES -t nat -A NAT_${1} -p $2 --dport $3 -j MARK --set-mark $forward_mark
  $IPTABLES -t nat -A NAT_${1} -p $2 -m mark --mark ${forward_mark}/${FMASK} -j DNAT --to $4:$5
#  $IPTABLES -t filter -A FORWARD_${1} -p $2 -d $4 --dport $5 -j ACCEPT
}

build_6forward_rule() {
  $IP6TABLES -t filter -A FORWARD_${1} -p $2 -d $3 --dport $4 -j ACCEPT
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

# ( "ZONE" "NAME OF PARAM - ex: F6T" "PROTO" )
parse_6forward() {
  get_param $2
  for fpar in $GET_PARAM
  do
    parse_comma $fpar
    build_6forward_rule $1 $3 $PARSE_COMMA
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

#    $IPTABLES -t mangle -N MARK_${zone}
    $IPTABLES -t nat    -N NAT_${zone}
    $IPTABLES -t filter -N INPUT_${zone}
#    $IPTABLES -t filter -N FORWARD_${zone}
#    $IPTABLES -t mangle -A PREROUTING -i $indev -d $in4ip -j MARK_${zone}
    $IPTABLES -t nat    -A PREROUTING -i $indev -d $in4ip -j NAT_${zone}
    $IPTABLES -t filter -A INPUT      -i $indev -d $in4ip -j INPUT_${zone}
#    $IPTABLES -t filter -A FORWARD    -i $indev -j FORWARD_${zone} # no $in4ip maybe vulnerability without "net.ipv4.conf.all.rp_filter = 1"
    if [ $snat != 'no' ]; then
      $IPTABLES -t nat    -A POSTROUTING -o $indev -s $snat  -j SNAT --to-source $in4ip
    fi
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
    parse_6forward $zone F6T tcp
  done
}

# ( $IPTABLES )
create_default(){
  local iptbl="$1"
  $iptbl -t filter -N CHECK-NEW-TCP
  $iptbl -t filter -A CHECK-NEW-TCP -p tcp --syn -j RETURN
  $iptbl -t filter -A CHECK-NEW-TCP -p tcp ! --tcp-flags SYN,ACK,FIN,RST SYN,ACK -j DROP
  $iptbl -t filter -A CHECK-NEW-TCP -p tcp -j REJECT --reject-with tcp-reset

  $iptbl -t filter -A INPUT -m state ! --state NEW -j DROP
  $iptbl -t filter -A INPUT -p tcp -j CHECK-NEW-TCP
  $iptbl -t filter -A INPUT -i lo -j ACCEPT

  $iptbl -t filter -A FORWARD -m state ! --state NEW -j DROP
  $iptbl -t filter -A FORWARD -p tcp -j CHECK-NEW-TCP
}

create_rules() {
  $IPTABLES -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IPTABLES -t filter -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  create_default "$IPTABLES"
  $IPTABLES -t filter -A INPUT -p icmp -j ACCEPT
  $IPTABLES -t filter -A FORWARD -m mark --mark $FFLAG/$FFLAG -j ACCEPT
  $IPTABLES -t filter -A INPUT   -m mark --mark $FFLAG/$FFLAG -j ACCEPT

  $IP6TABLES -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IP6TABLES -t filter -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IP6TABLES -t filter -A INPUT -p ipv6-icmp -j ACCEPT
  create_default "$IP6TABLES"

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
