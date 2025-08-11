from django.contrib import admin
from .models import User

# Register your models here.
class UserViewAdmin(admin.ModelAdmin):
    list_display = ('email', 'phone_number', 'first_name', 'last_name', 'address', 'location')

admin.site.register(User, UserViewAdmin)