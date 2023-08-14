from django.contrib import admin
from .models import Blogs
# Register your models here.
@admin.register(Blogs)
class BlogAdmin(admin.ModelAdmin):
    list_display = ('blog_name', 'writer', 'abstract', 'summary','titlefirst', 'contextfirst', 'titlesecond', 'contextsecond')
