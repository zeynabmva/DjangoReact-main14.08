# from .models import Blogs
# from django import forms


# class createBlog(forms.Form):
#     blog_name = forms.CharField(label='Blog name',max_length=350)
#     farmer = forms.CharField(max_length=350)
#     image = forms.ImageField(required=False)
#     blog_title = forms.CharField(widget=forms.Textarea, required=False)
#     summary = forms.CharField(widget=forms.Textarea, required=False)
#     title = forms.CharField(max_length=350, required=False)
#     context = forms.CharField(widget=forms.Textarea, required=False)
#     titlefirst = forms.CharField(label='First title',max_length=350, required=False)
#     contextfirst = forms.CharField(label='First context',widget=forms.Textarea, required=False)
#     titlesecond = forms.CharField(label='Second title',max_length=350, required=False)
#     contextsecond = forms.CharField(label='Second context',widget=forms.Textarea, required=False)
#     titlethird = forms.CharField(label='Third title',max_length=350, required=False)
#     contextthird = forms.CharField(label='Third context',widget=forms.Textarea, required=False)

# # class createBlog(forms.ModelForm):
# #     blog_name=forms.CharField(label="Blog name",max_length=350)
# #     farmer=forms.CharField(label="Farmer",max_length=350)
# #     titlefirst=forms.CharField(label="First title",max_length=350)
# #     titlesecond=forms.CharField(label="Second title",max_length=350)
# #     class Meta:
# #         model=Blogs
# #         exclude=("id","update_at","created_at")
    