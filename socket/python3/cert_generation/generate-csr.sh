#!/bin/bash
# if this script is running with "cleanup" as parameter, should delete all the keys from the hsm

#loading softhsm library
LIB='/usr/lib/softhsm/libsofthsm2.so'

# Set output path
output_path="/opt"

# list the available slots and check if the token label exists
token_label="secccoms"

# Function to derive IPv6 address from MAC address
function mac_to_ipv6() {
    # Remove any separators from the MAC address (e.g., colons, hyphens)
    mac_address="${1//[:\-]/}"
    mac_address="${mac_address,,}"

    # Split the MAC address into two equal halves
    first_half="${mac_address:0:6}"

    # Convert the first octet from hexadecimal to binary
    binary_first_octet=$(echo "obase=2; ibase=16; ${first_half:0:2}" | bc | xargs printf "%08d")

    # Invert the seventh bit (change 0 to 1 or 1 to 0)
    inverted_seventh_bit=$(( 1 - $(echo "${binary_first_octet:6:1}") ))

    # Convert the modified binary back to hexadecimal
    modified_first_octet=$(echo "obase=16; ibase=2; ${binary_first_octet:0:6}${inverted_seventh_bit}${binary_first_octet:7}" | bc)

    # Replace the original first octet with the modified one
    modified_mac_address="${modified_first_octet}${mac_address:2}"

    line="${modified_mac_address:0:6}fffe${modified_mac_address:6}"

    # Add "ff:fe:" to the middle of the new MAC address
    mac_with_fffe=$(echo "$line" | sed -r 's/(.{4})/\1:/g; s/:$//')

    echo "fe80::$mac_with_fffe"
}

# Read the user input for the network interface, defaulting to "wlp1s0" if no input is provided
#read -p "Enter the network interface (default: wlp1s0): " network_interface
#network_interface=${network_interface:-wlp1s0}

# Get the network interface from the command-line argument or use a default value
#network_interface=${1:-wlp1s0}
network_interface="wpl1s0"

# Parse the MAC address from the network interface using ip command
mac_address=$(ip link show "$network_interface" | awk '/ether/ {print $2}')

id=${mac_address//:/} #mac address with no colon

# Derive the IPv6 address from the MAC address (extended format)
ipv6_address=$(mac_to_ipv6 "$mac_address")


generate_pin()
{
  echo "Generating PIN"
  if [[ -f "$output_path/output.txt" ]]; then #pin exists load it
      #to decrypt
      pin=$(openssl aes-256-cbc -md sha256 -salt -a -pbkdf2 -iter 100000  -d  -k $id -in "$output_path"/output.txt) #We need to change this the pin obtained from the ID that is based on the mac
  else
      #random pin
      pin=$(tr -dc '0-9' </dev/random | head -c 6)
  fi
}

initialize_hsm()
{
  echo "Initializing HSM"
  #add line at the beginning of the file
sed -i '1s/^/openssl_conf = openssl_init\n/' /etc/ssl/openssl.cnf

# getting the system aarch64 or x86_64
system=$(uname -m)

#rpbi
if [[ "$system" == "aarch64" ]]; then
printf "\n[openssl_init]\nengines = engine_section\n\n[engine_section]\npkcs11 = pkcs11_section\n\n[pkcs11_section]\nengine_id = pkcs11\ndynamic_path = /usr/lib/engines-1.1/pkcs11.so\nMODULE_PATH = /usr/lib/softhsm/libsofthsm2.so" >> /etc/ssl/openssl.cnf
fi

#intel
if [[ "$system" == "x86_64" ]]; then
printf "\n[openssl_init]\nengines = engine_section\n\n[engine_section]\npkcs11 = pkcs11_section\n\n[pkcs11_section]\nengine_id = pkcs11\ndynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so #libP11/libpkcs11.so\nMODULE_PATH = /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" >> /etc/ssl/openssl.cnf
fi
}


initialize_all()
{
  echo "Initializing All"
  #intialize token
  pkcs11-tool --module="$LIB" --init-token --label secccoms --so-pin "$pin" # --pin "$pin"
  #init the pin
  pkcs11-tool --init-pin --login --pin "$pin" --so-pin "$pin" --module "$LIB"
}

hard_delete()
{
  echo "Hard Delete"
softhsm2_output=$(softhsm2-util --show-slot)
if [ ${#softhsm2_output} -ne 616 ]
 then
  echo "Token exists"
#  token_label=$(echo "$softhsm2_output" | grep 'Label:' | sed 's/^.*: //')
  serial=$(softhsm2-util --show-slot |grep Serial |awk '{print $3}')
  softhsm2-util --slot 1 --delete-token --serial "$serial"
#  softhsm2-util --slot 1 --delete-token --token "$token_label"
else
  echo "No Token exists"
fi
}

soft_delete()
{
echo "Soft Delete"
if pkcs11-tool --module="$LIB" --list-slots | grep -q "Label: $token_label"; then
  echo "Token exists"
  # delete the existing token
  pkcs11-tool --module="$LIB" --login --pin "$pin" --delete-token --label "$token_label" #we need the pin from previous execution
  #delete keys
  keys=$(pkcs11-tool --module="$LIB" -O --login --pin "$pin")
  if [ ${#keys} -ne 0  ]
  then
    echo "Keys Found"
    echo "Deleting old keys"
    pkcs11-tool --module="$LIB" --login --pin "$pin" --delete-object --type privkey --id 01
    pkcs11-tool --module="$LIB" --login --pin "$pin" --delete-object --type pubkey --id 01
  fi
else
  echo "No Token exists"
fi

}


export_pin()
{
#needs to be improved $LABEL is known
echo "exporting pin"
### Check if a directory does not exist ###
if [ ! -d "$output_path" ]
then
  mkdir -p "$output_path"
fi

if test -f "$output_path"/output.txt; then
    rm "$output_path"/output.txt
fi
echo "$pin" | openssl enc -aes-256-cbc -md sha256 -a -pbkdf2 -iter 100000 -salt -pass pass:$id > "$output_path"/output.txt
}



key_generation()
{

#generate keys
echo "Generating new keys"
#pkcs11-tool --keypairgen --key-type="RSA:4096"  --login --pin=$pin --module=$LIB --label=$LABEL --id=01
pkcs11-tool --keypairgen --key-type="EC:prime256v1"  --login --pin="$pin" --module="$LIB" --label="$id" --id=01 #for EC
#export to der
pkcs11-tool --read-object --id 01 --type pubkey --module="$LIB" --output-file macsec_"$id".key

# Generate the EC private key
#openssl ecparam -name prime256v1 -genkey -noout -out macsec_"$id".key  # for other certificates (eg ipsec) we need to verify if this exists

}


# Generate the 256-bit random number from the fingerprint of the public key
random=$(openssl ec -in macsec_"$id".key -pubout -outform DER | sha256sum | awk '{print substr($1, 1, 30)}')

# Derive the second IPv6 address (mesh IPv6) from the ID (extended format)
mesh_ipv6="fe80::$(echo "$random" | cut -c1-4):$(echo "$random" | cut -c5-8):$(echo "$random" | cut -c9-12)"


create_csr(){
echo "Generating CSR"
export OPENSSL_PIN="$pin"
# Create a CSR configuration file with the custom SANs
cat > csr.conf <<EOF
[req]
default_bits = 256
prompt = no
encrypt_key = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = $mac_address

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = csl$id.local
DNS.2 = cls$id.lan
IP.1 = $ipv6_address
IP.2 = $mesh_ipv6
EOF



# Create the CSR using the generated private key and the custom CSR configuration
openssl req -new -key macsec_"$id".key -engine pkcs11 -keyform engine -key 01 -passin env:OPENSSL_PIN -out macsec_"$id".csr -config csr.conf
echo "CSR generated: " "macsec_$id.csr"
openssl req -in macsec_"$id".csr -text -noout
}

input=$1

if [ "$input" == "cleanup" ]; then
  hard_delete
  soft_delete
  rm "$output_path"/output.txt
  rm csr.conf
  for file in mac_sec_*; do
    if [ -f "$file" ]; then
        rm "$file"
    fi
  done
  exit
fi

generate_pin
initialize_hsm
initialize_all
key_generation
export_pin
create_csr