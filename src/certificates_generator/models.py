import uuid

from django.db import models

# Create your models here.

class Certificate(models.Model):

    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    certifying_authority = models.SmallIntegerField(choices=[
        (0, "cerfificado de produccion"),
        (1, "cerfificado de desarrollo")
    ], verbose_name="Unidad cerfificadora")
    name = models.CharField(max_length=250, verbose_name="Nombre de la aplicación")
    domain = models.CharField(max_length=250, verbose_name="Dominio para el certificado ej. servicio.ucr.ac.cr")
    institution_unit = models.CharField(
        max_length=250, default="ND", verbose_name="Unidad en el certificado")
    private_key = models.TextField( verbose_name="Clave privada")
    public_key = models.TextField( verbose_name="Clave publica")
    public_certificate = models.TextField( verbose_name="Certificado publico")
    server_sign_key = models.TextField( verbose_name="Clave privada del servidor")
    server_public_key = models.TextField( verbose_name="Clave publica del servidor")
    state = models.SmallIntegerField(default=0, choices=[
        (0, 'Activo'),
        (1, 'Revocado')
    ], verbose_name="Estado")

    def __str__(self):
        return self.name

