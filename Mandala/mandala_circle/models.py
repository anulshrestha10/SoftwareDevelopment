from django.db import models
from django.core.validators import *
from django.core import validators
from django.contrib.auth.models import User
from django.db.models.deletion import CASCADE


# Models for admin form
class Product(models.Model):
    product_name = models.CharField(max_length=500, null=True, validators=[validators.MinLengthValidator(2)])
    product_price = models.FloatField()
    product_description = models.TextField(max_length=1000, null=True)
    product_image = models.ImageField(upload_to='static/uploads')
    created_date = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return self.product_name

class Gallery(models.Model):
    name = models.CharField(max_length=500, null=True, validators=[validators.MinLengthValidator(2)])
    image = models.ImageField(upload_to='static/gallery')

    def __str__(self):
        return self.name



class Order(models.Model):
    user = models.CharField(User,max_length=2000, null=True, blank=True)
    date_ordered = models.DateTimeField(auto_now_add=True)
    complete = models.BooleanField(default=False)
    transaction_id = models.CharField(max_length=100, null=True)

    def __str__(self):
        return str(self.id)

    @property
    def shipping(self):
        shipping = True
        orderitems = self.orderitem_set.all()
        return shipping

    @property
    def get_cart_total(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.get_total for item in orderitems])+100
        return total

    @property
    def get_cart_items(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.quantity for item in orderitems])
        return total


class OrderItem(models.Model):
    ORDER_STATUS = (
        ('pending', 'pending'),
        ('Delivered', 'Delivered'),
    )
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    order = models.ForeignKey(Order, on_delete=models.SET_NULL, null=True)
    quantity = models.IntegerField(default=0, null=True, blank=True)
    order_status = models.CharField(max_length=50, choices=ORDER_STATUS)
    date_added = models.DateTimeField(auto_now_add=True)
    delivered_status= models.BooleanField(default=False)


    @property
    def get_total(self):
        total = self.product.product_price * self.quantity
        return total

class ShippingAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    order = models.ForeignKey(Order, on_delete=models.SET_NULL, null=True)
    address = models.CharField(max_length=200, null=False)
    city = models.CharField(max_length=200, null=False)
    state = models.CharField(max_length=200, null=False)
    zipcode = models.CharField(max_length=200, null=False)
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.address


    @property
    def get_cart_total(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.get_total for item in orderitems]) + 100
        return total

# Models for user form
class Commission(models.Model):
    name = models.CharField(max_length=100, validators=[validators.MinLengthValidator(5)])
    email = models.EmailField()
    subject = models.CharField(max_length=100)
    message = models.TextField()

    def __str__(self):
        return self.name


class Feedback(models.Model):
    name = models.CharField(max_length=100, validators=[validators.MinLengthValidator(2)])
    product_feedback = models.TextField()

    def __str__(self):
        return self.product_feedback
