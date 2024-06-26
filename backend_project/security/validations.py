from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

UserModel = get_user_model()

def custom_validation(data):
    email = data.get('email', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'viewer').strip()  # Définir le rôle par défaut comme 'viewer'

    if not email or UserModel.objects.filter(email=email).exists():
        raise ValidationError('Choose another email.')
    
    if not password or len(password) < 8:
        raise ValidationError('Choose another password, min 8 characters.')
    
    if not username:
        raise ValidationError('Choose another username.')
    
    if role not in ['admin', 'tester', 'viewer']:
        raise ValidationError('Invalid role.')
    
    return data

def validate_email(data):
    email = data.get('email', '').strip()
    if not email:
        raise ValidationError('An email is needed.')
    return True

def validate_username(data):
    username = data.get('username', '').strip()
    if not username:
        raise ValidationError('Choose another username.')
    return True

def validate_password(data):
    password = data.get('password', '').strip()
    if not password:
        raise ValidationError('A password is needed.')
    return True
