from datetime import datetime
import hashlib
import OpenSSL

# Custom exceptions for certificate verification
class CertificateExpiredError(Exception):
    pass

class CertificateActivationError(Exception):
    pass

class CertificateHostnameError(Exception):
    pass

class CertificateIssuerError(Exception):
    pass

class CertificateVerificationError(Exception):
    pass

class CertificateNoPresentError(Exception):
    pass

def verify_cert(cert, logging):
    try:
        return validation(cert, logging)
    except (CertificateExpiredError, CertificateHostnameError, CertificateIssuerError, ValueError) as e:
        logging.error("Certificate verification failed.", exc_info=True)
        return False
    except Exception as e:
        logging.error("An unexpected error occurred during certificate verification.", exc_info=True)
        return False

def validation(cert, logging):
    # Load the DER certificate into an OpenSSL certificate object
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

    # Get the certificate expiration date and activation date using OpenSSL methods
    expiration_date_str = x509.get_notAfter().decode('utf-8')
    activation_date_str = x509.get_notBefore().decode('utf-8')

    expiration_date = datetime.strptime(expiration_date_str, '%Y%m%d%H%M%SZ')
    activation_date = datetime.strptime(activation_date_str, '%Y%m%d%H%M%SZ')
    current_date = datetime.now()

    # Check if the certificate has expired
    if expiration_date < current_date:
        logging.error("Certificate has expired.", exc_info=True)
        raise CertificateExpiredError("Certificate has expired.")

    if activation_date > current_date:
        logging.error("Client certificate not yet active.", exc_info=True)
        raise CertificateExpiredError("Client certificate not yet active")

    # Extract the public key from the certificate
    pub_key_der = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, x509.get_pubkey())

    # Compute the SHA256 hash of the public key
    hash_of_pub_key = hashlib.sha256(pub_key_der).hexdigest()

    # Extract ID from the CN (assuming the format is 'csl[ID]')
    expected_id = hash_of_pub_key[:30]  # taking the first 30 characters

    # Extract the actual ID from CN
    common_name = x509.get_subject().CN
    actual_id = common_name[3:]  # stripping off the "csl" prefix

    if actual_id != expected_id:
        logging.error("ID in the CN does not match the hash of the public key.", exc_info=True)
        raise ValueError("ID in the CN does not match the hash of the public key.")

    # Check if the certificate is issued by a trusted CA
    issuer = x509.get_issuer().CN
    trusted_ca = 'TII'  # Replace this with the trusted CA's distinguished name (DN)
    if issuer != trusted_ca:
        logging.error("Certificate issuer is not a trusted CA", exc_info=True)
        raise CertificateIssuerError(f"Certificate issuer '{issuer}' is not a trusted CA.")

    # Optionally, you can check other certificate properties like the key usage, extended key usage, etc.

    # If the client certificate has passed all verifications, you can print or log a success message
    logging.info("Certificate verification successful.")
    return True


# import threading
# myip='fe80::230:1aff:fe4f:c822'
#
# from auth.authServer import AuthServer
# from secure_channel.secchannel import SecMessageHandler
#
# auth_server = AuthServer(myip, 15001, "cert_generation/certificates/")
#
# auth_server_thread = threading.Thread(target=auth_server.start_server)
# auth_server_thread.start()
#
# secchan = SecMessageHandler(auth_server.get_secure_socket('fe80::230:1aff:fe4f:5b3c'))
# receiver_thread = threading.Thread(target=secchan.receive_message).start()
#
#
# import threading
# myip='fe80::230:1aff:fe4f:5b3c'
# serverip='fe80::230:1aff:fe4f:c822'
# from secure_channel.secchannel import SecMessageHandler
# from auth.authClient import AuthClient
#
# auth_client = AuthClient(serverip, 15001, "cert_generation/certificates/")
#
# a=auth_client.establish_connection()
# secchan = SecMessageHandler(auth_client.secure_client_socket)
# receiver_thread = threading.Thread(target=secchan.receive_message).start()
