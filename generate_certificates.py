#!/usr/bin/env python3
import argparse
import subprocess
import os

def generate_certificates(fake_prefix=False):
    # Set the common name (CN) for the server and client certificates
    server_common_name = "server"
    client_common_name = "client"

    # Set the path to the OpenSSL configuration file
    openssl_cnf = "../openssl.cnf"

    # Create a directory to store the certificates
    os.makedirs("certificates", exist_ok=True)
    os.chdir("certificates")

    # Generate the Certificate Authority (CA) key and self-signed certificate
    ca_key_path = "ca.key"
    ca_crt_path = "ca.crt"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            ca_key_path,
        ],
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            ca_key_path,
            "-out",
            ca_crt_path,
            "-days",
            "365",
            "-subj",
            "/CN=TII",
            "-config",
            openssl_cnf,
        ],
        check=True,
    )

    # Generate the server key and certificate signing request (CSR)
    server_key_path = "server.key"
    server_csr_path = "server.csr"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            server_key_path,
        ],
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            server_key_path,
            "-out",
            server_csr_path,
            "-subj",
            f"/CN={server_common_name}",
            "-config",
            openssl_cnf,
        ],
        check=True,
    )

    # Sign the server CSR with the CA to get the server certificate
    server_crt_path = "server.crt"
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            server_csr_path,
            "-CA",
            ca_crt_path,
            "-CAkey",
            ca_key_path,
            "-CAcreateserial",
            "-out",
            server_crt_path,
            "-days",
            "365",
            "-extensions",
            "server_cert",
            "-extfile",
            openssl_cnf,
        ],
        check=True,
    )

    # Generate the client key and certificate signing request (CSR)
    client_key_path = "client.key"
    client_csr_path = "client.csr"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            client_key_path,
        ],
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            client_key_path,
            "-out",
            client_csr_path,
            "-subj",
            f"/CN={client_common_name}",
            "-config",
            openssl_cnf,
        ],
        check=True,
    )

    # Sign the client CSR with the CA to get the client certificate
    client_crt_path = "client.crt"
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            client_csr_path,
            "-CA",
            ca_crt_path,
            "-CAkey",
            ca_key_path,
            "-CAcreateserial",
            "-out",
            client_crt_path,
            "-days",
            "365",
            "-extensions",
            "usr_cert",
            "-extfile",
            openssl_cnf,
        ],
        check=True,
    )

    # Clean up the temporary CSR files
    os.remove(server_csr_path)
    os.remove(client_csr_path)

    # Print the output with or without the "FAKE" prefix based on the parameter
    if fake_prefix:
        fake_cert_path = "certificates/fake"
        print(f"Certificates have been generated successfully in the '{fake_cert_path}' directory.")
    else:
        print("Certificates have been generated successfully in the 'certificates' directory.")
        fake_cert_path = "certificates/"
    # Create a new directory named 'fake' to store the certificates with their normal names
    fake_cert_path = os.path.join(os.pardir, fake_cert_path)
    os.makedirs(fake_cert_path, exist_ok=True)

    # Move the certificates to the 'fake' folder
    os.rename(ca_key_path, os.path.join(fake_cert_path, ca_key_path))
    os.rename(ca_crt_path, os.path.join(fake_cert_path, ca_crt_path))
    os.rename(server_key_path, os.path.join(fake_cert_path, server_key_path))
    os.rename(server_crt_path, os.path.join(fake_cert_path, server_crt_path))
    os.rename(client_key_path, os.path.join(fake_cert_path, client_key_path))
    os.rename(client_crt_path, os.path.join(fake_cert_path, client_crt_path))


    print("Verifying certificates...\n")

    # Verify the certificates in the 'fake' folder
    subprocess.run(
        ["openssl", "verify", "-CAfile", os.path.join(fake_cert_path, ca_crt_path), os.path.join(fake_cert_path, "client.crt")], check=True
    )
    subprocess.run(
        ["openssl", "verify", "-CAfile", os.path.join(fake_cert_path, ca_crt_path), os.path.join(fake_cert_path, "server.crt")], check=True
    )


def main():
    parser = argparse.ArgumentParser(description="Certificate Generation Script")
    parser.add_argument(
        "--fake",
        action="store_true",
        help="Create a new folder 'fake' to store the certificates with their normal names.",
    )
    args = parser.parse_args()

    generate_certificates(fake_prefix=args.fake)


if __name__ == "__main__":
    main()
