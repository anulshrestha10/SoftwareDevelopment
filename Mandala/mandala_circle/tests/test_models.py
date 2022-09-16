from django.test.testcases import TestCase
from accounts.models import Profile
from mandala_circle.models import Commission


class TestModels(TestCase):
    def setUp(self):
        pass

    # function to test url for Commission
    def text_commission(self):
        com = Commission.objects.create(
            name = "Test name",
            message = "Test message"
        )
        self.assertIsNotNone(Commission.objects.filter(name="Test name"))

    # function to test url for Profile
    def text_profile(self):
        profile = Profile.objects.create(
            firstname="Profile",
            created_date="2010/05/5"

        )
        self.assertIsNotNone(Profile.objects.filter(name=" Profile"))
