from django.contrib import admin
from .models import CustomUser, PasswordResetCode

class PasswordResetCodeInline(admin.TabularInline):
    model = PasswordResetCode
    extra = 0  # No extra empty forms by default

class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'phone_number', 'is_staff', 'is_active', 'status')  # Updated fields
    list_filter = ('is_staff', 'is_active', 'status')  # Filters for the sidebar
    search_fields = ('email', 'first_name', 'last_name')  # Updated searchable fields
    ordering = ('email',)  # Default ordering
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'phone_number')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'status')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'phone_number', 'password', 'is_staff', 'is_active', 'status'),
        }),
    )
    inlines = [PasswordResetCodeInline]  # Add inline for reset codes
    actions = ['deactivate_users', 'activate_users']  # Add custom actions

    def deactivate_users(self, request, queryset):
        """
        Custom action to deactivate selected users.
        """
        updated = queryset.update(is_active=False, status='deactivate')
        self.message_user(request, f'Successfully deactivated {updated} users.')

    deactivate_users.short_description = "Deactivate selected users"

    def activate_users(self, request, queryset):
        """
        Custom action to activate selected users.
        """
        updated = queryset.update(is_active=True, status='active')
        self.message_user(request, f'Successfully activated {updated} users.')

    activate_users.short_description = "Activate selected users"

class PasswordResetCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'created_at')  # Fields to display in the list view
    list_filter = ('created_at',)  # Filters for the sidebar
    search_fields = ('code', 'user__email')  # Searchable fields
    ordering = ('-created_at',)  # Order by creation time, newest first

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(PasswordResetCode, PasswordResetCodeAdmin)