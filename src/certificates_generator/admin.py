from datetime import datetime

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib import admin, messages
from django.http import HttpResponse
from django.shortcuts import redirect, get_object_or_404, render
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from .admin_views import CertificateAdminMixin
from .forms import CertificateForm
from .models import Certificate
from django.conf import settings


# Register your models here.

@admin.register(Certificate)
class CertificateAdmin(CertificateAdminMixin, admin.ModelAdmin):
    form = CertificateForm
    list_display = ('name', 'user','institution_unit','state','revoke_certificate_admin')

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_add_permission(self, request):
        return request.user.is_superuser

    def has_change_permission(self, request, obj=None):
        return request.user.is_superuser

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser

    def revoke_certificate_admin(self, obj):
        return format_html(
            '<a class="button" href="{}">Revocar certificado</a>&nbsp;'
            '<a class="button" href="{}">Regenerar llaves</a>&nbsp'
            '<a class="button" href="{}">Verificar OSCP</a>',
            f'/admin/certificates_generator/certificate/{obj.pk}/revoke_certificate/',
            f'/admin/certificates_generator/certificate/{obj.pk}/regenerate_keys/',
            f'/admin/certificates_generator/certificate/{obj.pk}/verify_oscp/',
        )
    revoke_certificate_admin.short_description = "Acciones"
    revoke_certificate_admin.allow_tags = True

    # Override get_urls method

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('<path:object_id>/view_keys/', self.admin_site.admin_view(self.view_keys), name='view_keys'),
            path('<path:object_id>/revoke_certificate/', self.admin_site.admin_view(self.revoke_certificate_view),
                 name='revoke_certificate'),
            path('<path:object_id>/regenerate_keys/', self.admin_site.admin_view(self.regenerate_keys),
                 name='regenerate_keys'),
            path('<path:object_id>/verify_oscp/', self.admin_site.admin_view(self.verify_oscp),
                 name='verify_oscp'),
        ]
        return custom_urls + urls

    def regenerate_keys(self, request, object_id):
        obj = get_object_or_404(Certificate, pk=object_id)

        if request.method == "POST":
            try:
                self.revoke_certificate(obj)
                self.save_model(request, obj, None, False)
                messages.success(request, f"Las llaves del certificado de {obj.name} fueron regeneradas correctamente.")
            except Exception as e:
                messages.error(request, f"Error al revocar el certificado: {str(e)}")
            return redirect(reverse('admin:view_keys', args=[obj.pk]))

        context = {
            'object': obj,
            'title': '¿Está seguro que desea regenerar las llaves?',
            'opts': self.model._meta,
            'object_id': object_id,
        }
        return render(request, 'confirm_regenerate_keys.html', context)

    def revoke_certificate_view(self, request, object_id):
        obj = get_object_or_404(Certificate, pk=object_id)

        if request.method == "POST":
            try:
                self.revoke_certificate(obj)
                messages.success(request, f"El certificado de {obj.name} fue revocado correctamente.")
            except Exception as e:
                messages.error(request, f"Error al revocar el certificado: {str(e)}")
            return redirect('/admin/certificates_generator/certificate/')

        context = {
            'object': obj,
            'title': '¿Está seguro que desea revocar este certificado?',
            'opts': self.model._meta,
            'object_id': object_id,
        }
        return render(request, 'confirm_revoke_keys.html', context)

    def view_keys(self, request, object_id):
        keys = request.session.pop('temp_keys', None)
        if not keys:
            return HttpResponse("Esta página ya no está disponible o las llaves ya fueron eliminadas.", status=410)

        return TemplateResponse(request, "show_keys.html", {
            'private_key': keys['private_key'],
            'public_key': keys['public_key'],
            'public_certificate': keys['public_certificate'],
        })

    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        if object_id is not None and request.method == 'POST':
            obj = self.get_object(request, object_id)
            if obj and obj.public_certificate:
                messages.error(request, "La edición de certificados no está permitida.")
                return redirect(reverse('admin:certificates_generator_certificate_changelist'))

        return super().changeform_view(request, object_id, form_url, extra_context)

    def verify_oscp(self, request, object_id):
        obj = get_object_or_404(Certificate, pk=object_id)
        try:
            is_valid = self.validate_ocsp_details(obj)
            if not is_valid:
                messages.error(request, f"El certificado de {obj.name} no es válido.")
                return redirect(reverse('admin:view_keys', args=[obj.pk]))
            messages.success(request, f"El certificado de {obj.name} fue verificado correctamente.")
        except Exception as e:
            messages.error(request, f"Error al verificar el certificado: {str(e)}")
        return redirect('/admin/certificates_generator/certificate/')
