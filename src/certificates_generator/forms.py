from .models import Certificate
from django.utils.safestring import mark_safe
from django import forms

class CertificateForm(forms.ModelForm):
    class Meta:
        model = Certificate
        fields = [
            'name', 'domain',
            'certifying_authority', 'institution_unit',
            'private_key', 'public_key', 'public_certificate',
            'server_sign_key', 'server_public_key',
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        read_only_fields = [
            'private_key', 'public_key', 'public_certificate',
            'server_sign_key', 'server_public_key'
        ]

        for field in read_only_fields:
            self.fields[field].required = False
            self.fields[field].disabled = True
            pem_content = self.initial.get(field, '')
            extension = self.get_extension(field)
            filename = f"{field}.{extension}"

            self.fields[field].widget = forms.widgets.Textarea(attrs={
                'readonly': 'readonly',
                'style': 'font-family: monospace; width: 90%; height: 120px;',
            })

            if field == 'private_key':
                continue

            if pem_content:
                download_button = f'''
                    <a download="{filename}" href="data:application/x-pem-file;charset=utf-8,{pem_content}" 
                       style="margin-top: 5px; display: inline-block;" class="button">
                       Descargar {extension.upper()}
                    </a>
                '''
                self.fields[field].help_text = mark_safe(download_button)

    def get_extension(self, field_name):
        if 'private_key' in field_name:
            return 'key'
        if 'public_key' in field_name:
            return 'pub'
        if 'certificate' in field_name:
            return 'crt'
        return 'pem'
