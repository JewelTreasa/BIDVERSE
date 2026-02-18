from django import forms
from .models import User

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone', 'address', 'business_name', 'gstin', 'pan_number', 'bank_account_number', 'bank_ifsc_code', 'bank_name']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'business_name': forms.TextInput(attrs={'class': 'form-control'}),
            'gstin': forms.TextInput(attrs={'class': 'form-control'}),
            'pan_number': forms.TextInput(attrs={'class': 'form-control'}),
            'bank_account_number': forms.TextInput(attrs={'class': 'form-control'}),
            'bank_ifsc_code': forms.TextInput(attrs={'class': 'form-control'}),
            'bank_name': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def clean_address(self):
        address = self.cleaned_data.get('address')
        if not address or len(address.strip()) < 10:
            raise forms.ValidationError("Please provide a valid, complete address (minimum 10 characters).")
        return address

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Hide farmer fields for non-farmers dynamically in template or view logic
        # But for form definition, we include them all.
