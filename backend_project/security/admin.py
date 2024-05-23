from django.contrib import admin
from .models import AppUser

@admin.register(AppUser)
class AppUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'role', 'is_active', 'is_staff')
    search_fields = ('email', 'username')
    readonly_fields = ('user_id',)

    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
