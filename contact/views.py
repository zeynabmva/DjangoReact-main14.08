
from django.shortcuts import render

# Create your views here.
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import Contact
from django.core.mail import send_mail
from django.conf import settings

@csrf_exempt
def contact_view(request):
    if request.method == 'POST':
        # Get the raw JSON data from the request body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data.'}, status=400)

        # Extract name, email, and message from the JSON data
        name = data.get('name')
        email = data.get('email')
        message = data.get('message')

        if not name or not email or not message:
            return JsonResponse({'error': 'All fields are required.'}, status=400)

        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({'error': 'Invalid email address.'}, status=400)

        try:
            contact = Contact(name=name, email=email, message=message)
            contact.save()

            subject = 'Teşekkürler!'
            message = f"Merhaba {name},\n\nİletişim bilgileriniz başarıyla kaydedildi. Size en kısa sürede dönüş yapacağız."
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email]
            
            try:
                send_mail(subject, message, from_email, recipient_list)
                return JsonResponse({'success': True})
            except Exception as e:
                print(e)
                return JsonResponse({'error': 'An error occurred while sending the email.'}, status=500)
        except Exception as e:
            return JsonResponse({'error': 'An error occurred while saving the contact.'}, status=500)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed.'}, status=400)