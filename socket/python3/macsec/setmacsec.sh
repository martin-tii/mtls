#!/bin/bash
### This command should be executed as ./run_macsec.sh <up/down> <interface> <primary/secondary>
### up is to set the interface up
### primary means the first node that will be running (will get the key1)
###

configure_macsec()
{
  echo "Configuring MACsec"

  source variables.conf
  interface=$INTERFACE
  status=$STATUS
  role=$ROLE
  key1=$KEY1
  key2=$KEY2
  ipprim=$IPPRIM
  ipseco=$IPSECO

#  get_interface_mac()
#  {
#    echo "$(ip -brief link | grep "$interface" | awk '{print $3; exit}')"
#  }

  down()
  {
    echo "Shutting down MACSec for $interface"
    ip link set dev "$interface" down
  }

  up()
  {
    echo "Setting up MACSec for $interface"
    ip link set dev "$interface" up

    if [[ "$role" == "primary" ]]; then
      # Add outgoing policy
      ip xfrm state add src "$ipprim" dst "$ipseco" proto esp spi 0x01 mode transport aead 'rfc4106(gcm(aes))' "$key1" 128
      # Add incoming policy
      ip xfrm state add src "$ipseco" dst "$ipprim" proto esp spi 0x02 mode transport aead 'rfc4106(gcm(aes))' "$key2" 128
    else
      # Add outgoing policy
      ip xfrm state add src "$ipseco" dst "$ipprim" proto esp spi 0x01 mode transport aead 'rfc4106(gcm(aes))' "$key2" 128
      # Add incoming policy
      ip xfrm state add src "$ipprim" dst "$ipseco" proto esp spi 0x02 mode transport aead 'rfc4106(gcm(aes))' "$key1" 128
    fi

    # Set the MTU of the interface to account for IPsec overhead
    mtu=$((1500 - 20 - 8 - 8)) # 20 bytes for IP header, 8 bytes for ESP header, 8 bytes for ICV
    ip link set dev "$interface" mtu "$mtu"

    ip a add "$ipseco"/24 dev "$interface"
    echo "IP: $ipseco/24"
  }

  if [ "$status" == "down" ]; then
    down "$interface"
  fi

  if [ "$status" == "up" ]; then
    up "$interface"
  fi
}

configure_macsec
ip xfrm state
