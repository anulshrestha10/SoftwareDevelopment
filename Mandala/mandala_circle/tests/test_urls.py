from django.test import SimpleTestCase
from django.urls import reverse,resolve
from accounts.views import homepage
from mandala_circle.views import about_me


class TestUrls(SimpleTestCase):
    # function to test url for homepage
    def test_homepage_url(self):
        url = reverse('home')
        self.assertEqual(resolve(url).func,homepage)

    # function to test url for aboutme
    def test_aboutme_url(self):
        url = reverse('about')
        self.assertEqual(resolve(url).func,about_me)











