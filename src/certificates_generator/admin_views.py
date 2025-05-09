import re
from datetime import timedelta

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from django.shortcuts import redirect
from django.urls import reverse


from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from django.conf import settings
from django.utils.timezone import now
from django_ca.constants import ReasonFlags
from django.core.exceptions import ValidationError

from django_ca.models import Certificate
from django_ca.models import CertificateAuthority

from .utils import CertificateUtils


class CertificateAdminMixin:
    utils = CertificateUtils()

    # Override save_model method

    def save_model(self, request, save_model, form, change):
        api_url = settings.DJANGO_CA_URL_PATH
        user = settings.DJANGO_CA_USER
        password = settings.DJANGO_CA_USER_PASSWORD
        serial_DEV = settings.DJANGO_CA_SERIAL_DEVELOPMENT
        serial_PROD = settings.DJANGO_CA_SERIAL_PRODUCTION

        save_model.user = request.user

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        csr = self._build_csr(private_key, save_model)

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        subject = self.utils.build_subject(save_model)

        response_data = self.sign_certificate(csr_pem, subject, self.utils.get_serial(save_model.certifying_authority),api_url,user,password)
        if response_data is None:
            raise ValidationError(f"La solicitud {api_url} para firmar el certificado falló. Intenta nuevamente.")
        response_data = self.utils.get_certificate(response_data["slug"], self.utils.get_serial(save_model.certifying_authority), api_url, user, password)
        if response_data is None:
            raise ValidationError(f"La solicitud {api_url} para firmar el certificado falló. Intenta nuevamente.")
        certificate_pem = response_data["pem"].encode()

        save_model.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        save_model.public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        save_model.public_certificate = certificate_pem.decode()

        server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        save_model.server_sign_key = server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        save_model.server_public_key = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        request.session['temp_keys'] = {
            'private_key': save_model.private_key,
            'public_key': save_model.server_public_key,
            'public_certificate': save_model.public_certificate,
        }

        save_model.private_key = "La clave privada no se almacena, si la perdió, debera regenerar las llaves"
        save_model.state = 0

        super().save_model(request, save_model, form, change)

    def response_add(self, request, obj, post_url_continue=None):
        return redirect(
            reverse('admin:view_keys', args=[obj.pk])
        )

    def response_change(self, request, obj):
        return redirect(
            reverse('admin:view_keys', args=[obj.pk])
        )

    def _build_csr(self, private_key, save_model):
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(
            x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "CR"),
                x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "San Jose"),
                x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Costa Rica"),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "UCR"),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, save_model.institution_unit),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, save_model.domain),
            ]))
        csr = csr_builder.sign(private_key, hashes.SHA256())
        return csr

    def sign_certificate(self, csr_pem, subject, serial, api_url, user, password):
        url = f"{api_url}ca/{serial}/sign/"
        payload = {
            "csr": csr_pem.decode(),
            "subject": subject,
            "profile": "webserver"
        }

        response = requests.post(
            url,
            auth=(user, password),
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            return response.json()
        else:
            return None
    """
    def oscp_extension(self, serial):
        ocsp_url = f"http://{settings.CA_DEFAULT_HOSTNAME}/ocsp/"
        ocsp_extension = x509.Extension(
            oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            critical=False,
            value=AuthorityInformationAccess([
                AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    UniformResourceIdentifier(ocsp_url)
                )
            ])
        )
        return ocsp_extension
    """

    # Override Delete methods

    def delete_model(self, request, obj):
        self.revoke_certificate(obj)
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            self.revoke_certificate(obj)
        super().delete_queryset(request, queryset)

    def revoke_certificate(self, obj):
        try:
            serial = self.get_serial_from_pem(obj.public_certificate)
            cert = Certificate.objects.get(serial=serial)
            if cert is None:
                return True
            cert.revoke(reason=ReasonFlags.remove_from_crl, compromised=now())
            obj.state = 1
            obj.save()
            return True
        except Exception as e:
            print(f"Error revoking certificate: {e}")
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

    def load_csr(self, csr_pem: bytes | str) -> x509.CertificateSigningRequest:
        if isinstance(csr_pem, str):
            csr_pem = csr_pem.encode("utf-8")
        return x509.load_pem_x509_csr(csr_pem, backend=default_backend())

    def format_serial(self, serial_number: int) -> str:
        hex_str = f"{serial_number:X}"

        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str

        return hex_str

    # ValidateOcsp method
    def validate_ocsp_details(self, certificate):

        certificate_str = re.sub(r'\\n', '\n', certificate.public_certificate)
        cert = x509.load_pem_x509_certificate(certificate_str.encode(), default_backend())
        try:
            if certificate.certifying_authority == 0:
                serial = settings.DJANGO_CA_SERIAL_PRODUCTION
            else:
                serial = settings.DJANGO_CA_SERIAL_DEVELOPMENT
            issuer = self.get_issuer_certificate(serial)
            ocsp_ulr = self.get_certificate_ocsp_url(cert)
            #ocsp_ulr = ocsp_ulr + self.get_serial_from_pem(certificate_str) +"/cert/"
            if not ocsp_ulr:
                print(f"Error al obtener la url de OCSP")
                return False
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer, hashes.SHA1())
            ocsp_request = builder.build()
            headers = {
                "Content-Type": "application/ocsp-request",
            }
            response = requests.post(ocsp_ulr, data=ocsp_request.public_bytes(serialization.Encoding.DER),
                                     headers=headers)
            if response.status_code != 200:
                print(f"Respuesta OCSP no válida (código {response.status_code})")
                return False
            ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)

            if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
                print(f"Respuesta OCSP no válida (código {response.status_code})")
                return False
            status = ocsp_response.certificate_status
            if status == x509.ocsp.OCSPCertStatus.GOOD:
                print(f"Certificate valid")
                return True
            elif status == x509.ocsp.OCSPCertStatus.REVOKED:
                print(f"Certificate revoked")
                return False
            elif status == x509.ocsp.OCSPCertStatus.UNKNOWN:
                print(f"Certificate unknown")
                return False

        except Exception as e:
            print(f"Error al validar el certificado: {e}")
            raise
        

    def get_issuer_certificate(self, serial) -> x509.Certificate:
        try:
            ca = CertificateAuthority.objects.get(serial=serial)
            pem_data = ca.pub.pem
            issuer_cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), default_backend())
            return issuer_cert
        except Exception as e:
            print(f"Error al obtener el certificado de la CA: {e}")
            raise

    def get_certificate_ocsp_url(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value

            ocsp_url = None
            for access_desc in aia:
                if access_desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp_url = access_desc.access_location.value
                    break

            if ocsp_url:
                return ocsp_url
            else:
                print(f"No OCSP URL found")
                return None
        except Exception as e:
            print(f"Error al obtener el certificado de la CA: {e}")
            raise