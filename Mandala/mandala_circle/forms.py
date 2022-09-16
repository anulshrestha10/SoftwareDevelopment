from django import forms
from django.forms import ModelForm
from .models import Commission,Feedback,Product,Gallery

# For Admin page
class OriginalForm(ModelForm):
    class Meta:
        model = Product
        fields = "__all__"

class GalleryForm(ModelForm):
    class Meta:
        model = Gallery
        fields = "__all__"

#For user Page

class CommissionForm(ModelForm):
    class Meta:
        model = Commission
        fields = "__all__"

class FeedbackForm(ModelForm):
    class Meta:
        model = Feedback
        fields = "__all__"
    

