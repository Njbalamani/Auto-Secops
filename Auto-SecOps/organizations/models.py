from django.db import models


class Organization(models.Model):
    name = models.CharField(max_length=180)
    slug = models.SlugField(max_length=120, unique=True)
    industry = models.CharField(max_length=120, blank=True)
    description = models.TextField(blank=True)
    synthetic = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
