from django.core.management.base import BaseCommand
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from base64 import urlsafe_b64encode
import jwt

class Command(BaseCommand):
    help = 'Generates a VAPID key pair'

    def handle(self, *args, **options):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        public_key_b64 = urlsafe_b64encode(public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).rstrip(b'=').decode('utf-8')

        private_key_b64 = urlsafe_b64encode(private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).rstrip(b'=').decode('utf-8')

        vapid_jwt = jwt.encode({
            'aud': 'http://localhost:4200',
            'exp': 9999999999,
            'sub': 'mailto:wurkdev@gmail.com',
            'public_key': public_key_b64,
            'private_key': private_key_b64,
        }, private_key, algorithm='RS256')

        self.stdout.write(self.style.SUCCESS('VAPID key pair generated successfully!'))
        self.stdout.write(self.style.SUCCESS(f'Public key: {public_key_b64}'))
        self.stdout.write(self.style.SUCCESS(f'Private key: {private_key_b64}'))
        self.stdout.write(self.style.SUCCESS(f'VAPID JWT: {vapid_jwt}'))
