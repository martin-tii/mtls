from datetime import datetime
import logging

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

def verify_cert(cert, hostname):
    # Perform custom certificate verification here
    # For example, you can check the certificate's expiration date, subject, issuer, etc.

    # Get the certificate expiration date
    expiration_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    activation_date = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
    current_date = datetime.now()

    # Check if the certificate has expired
    if expiration_date < current_date:
        # raise ValueError("Certificate has expired.")
        logging.error("Certificate has expired.", exc_info=True)
        raise CertificateExpiredError("Certificate has expired.")

    if activation_date > current_date:
        logging.error("Client certificate not yet active.", exc_info=True)
        raise CertificateExpiredError("Client certificate not yet active")

    # Check if the certificate's common name (CN) matches the expected hostname or IP address
    common_name = cert['subject'][0][0][1]

    if common_name != hostname: # shuld be hostname or IP
        logging.error("Certificate common name does not match the expected hostname.", exc_info=True)
        raise CertificateHostnameError(f"Certificate common name '{common_name}' does not match the expected hostname.")

    # Check if the certificate is issued by a trusted CA
    issuer = cert['issuer'][0][0][1]
    trusted_ca = 'TII'  # Replace this with the trusted CA's distinguished name (DN)
    if issuer != trusted_ca:
        logging.error("Certificate issuer is not a trusted CA", exc_info=True)
        raise CertificateIssuerError(f"Certificate issuer '{issuer}' is not a trusted CA.")

    # Optionally, you can check other certificate properties like the key usage, extended key usage, etc.

    # If the client certificate has passed all verifications, you can print or log a success message
    print("Certificate verification successful.")
    logging.info("Certificate verification successful.")