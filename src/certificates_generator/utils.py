import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from django.contrib.admin import filters
from django_ca.api.utils import get_certificate_authority
from django_ca.models import CertificateOrder, Certificate


class CertificateUtils:

    def get_serial(self, intermediate_type, serial_DEV, serial_PROD):
        serial = serial_DEV
        if intermediate_type == 0:
            serial = serial_PROD
        return serial

    def get_certificate(self, slug, serial, api_url, user, password):
        try:
            url = f"{api_url}ca/{serial}/orders/{slug}/"
            response = requests.get(
                url,
                auth=(user, password),
                headers={
                    "Content-Type": "application/json"
                }
            )
            response.raise_for_status()
            cert_serial = response.json()["serial"]
            url = f"{api_url}ca/{serial}/certs/{cert_serial}/"
            response = requests.get(
                url,
                auth=(user, password),
                headers={
                    "Content-Type": "application/json"
                }
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error al obtener el certificado: {e}")
            raise
    def get_serial_from_pem(self, pem_data: str) -> str:
        try:
            cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), default_backend())
            serial_int = cert.serial_number
            serial_hex = f"{serial_int:x}".upper()
            if len(serial_hex) % 2 != 0:
                serial_hex = serial_hex
            return serial_hex
        except Exception as e:
            print("Error al procesar el certificado:", e)
            raise

    def build_subject(self, save_model):
        return [
            {"oid": "2.5.4.6", "value": "CR"},  # Country
            {"oid": "2.5.4.8", "value": "San Jose"},  # State
            {"oid": "2.5.4.7", "value": "Costa Rica"},  # Locality
            {"oid": "2.5.4.10", "value": save_model.name},  # Organization
            {"oid": "2.5.4.11", "value": save_model.institution_unit},  # Organizational Unit
            {"oid": "2.5.4.3", "value": save_model.domain},  # Common Name
        ]