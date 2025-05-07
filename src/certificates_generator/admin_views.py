from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from datetime import datetime
import requests

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings

from .models import Certificate
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

        response_data = self.sign_certificate(csr_pem, subject, self.utils.get_serial(save_model.certifying_authority,serial_DEV,serial_PROD), api_url, user, password)
        slug = response_data["slug"]
        response_data = self.utils.get_certificate(slug, self.utils.get_serial(save_model.certifying_authority,serial_DEV,serial_PROD), api_url, user, password)
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

        response.raise_for_status()
        return response.json()


    # Override Delete methods

    def delete_model(self, request, obj):
        self.revoke_certificate(obj)
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            self.revoke_certificate(obj)
        super().delete_queryset(request, queryset)

    def revoke_certificate(self, obj):
        api_url = settings.DJANGO_CA_URL_PATH
        user = settings.DJANGO_CA_USER
        password = settings.DJANGO_CA_USER_PASSWORD
        serial_DEV = settings.DJANGO_CA_SERIAL_DEVELOPMENT
        serial_PROD = settings.DJANGO_CA_SERIAL_PRODUCTION
        try:
            serial = self.utils.get_serial_from_pem(obj.public_certificate)

            url = f"{api_url}ca/{serial}/revoke/{serial_DEV}/"
            if obj.certifying_authority == 0:
                url = f"{api_url}ca/{serial_PROD}/revoke/{serial}/"
            compromised_time = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
            data = {
                "compromised": compromised_time,
                "reason": "removeFromCRL"
            }
            response = requests.post(
                url,
                auth=(user, password),
                headers={
                    "Content-Type": "application/json"
                },
                json=data
            )
            state = response.status_code
            if state == 200 or state == 400:
                obj.state = 1
                obj.save()
            else:
                raise Exception(f"Error al revocar el certificado: {response.text}")
            return True
        except Exception as e:
            print(f"Error al revocar el certificado: {e}")
            raise