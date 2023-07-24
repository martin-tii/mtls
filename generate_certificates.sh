#!/bin/bash

# Set the common name (CN) for the server and client certificates
server_common_name="server"
client_common_name="client"

# Set the path to the OpenSSL configuration file
openssl_cnf="../openssl.cnf"

# Create a directory to store the certificates
mkdir -p certificates
cd certificates

# Generate the Certificate Authority (CA) key and self-signed certificate
openssl genpkey -algorithm RSA -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=TII" -config "$openssl_cnf"

# Generate the server key and certificate signing request (CSR)
openssl genpkey -algorithm RSA -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=${server_common_name}" -config "$openssl_cnf"

# Sign the server CSR with the CA to get the server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions server_cert -extfile "$openssl_cnf"

# Generate the client key and certificate signing request (CSR)
openssl genpkey -algorithm RSA -out client.key
openssl req -new -key client.key -out client.csr -subj "/CN=${client_common_name}" -config "$openssl_cnf"

# Sign the client CSR with the CA to get the client certificate
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -extensions usr_cert -extfile "$openssl_cnf"

# Clean up the temporary CSR files
rm *.csr

echo "Certificates have been generated successfully in the 'certificates' directory."

echo "Verifying certificates"


openssl verify -CAfile ca.crt client.crt

openssl verify -CAfile ca.crt server.crt