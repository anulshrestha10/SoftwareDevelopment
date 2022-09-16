from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import CommissionForm, FeedbackForm, OriginalForm,GalleryForm
from .models import *
from accounts.auth import unauthenticated_user, admin_only, user_only
from django.contrib.auth.decorators import login_required
import os
from .utils import *
from django.http import JsonResponse
import datetime
import json


# Footer function
def privacy_policy(request):
    data = cartData(request)

    cartItems = data['cartItems']
    context ={
        'cartItems': cartItems
    }
    return render(request, 'mandala_circle/privacyPolicy.html',context)


def refund_policy(request):
    data = cartData(request)

    cartItems = data['cartItems']
    context = {
        'cartItems': cartItems
    }
    return render(request, 'mandala_circle/refundPolicy.html',context)


def term_condition(request):
    data = cartData(request)

    cartItems = data['cartItems']
    context = {
        'cartItems': cartItems
    }
    return render(request, 'mandala_circle/termCondition.html',context)


def learn_mandala(request):
    data = cartData(request)

    cartItems = data['cartItems']
    context = {
        'cartItems': cartItems
    }
    return render(request, 'mandala_circle/learnMandala.html',context)


# Header function
#Personal Information Display
def about_me(request):
    data = cartData(request)

    cartItems = data['cartItems']
    context = {
        'cartItems': cartItems,
        'activate_about_me': 'active'
    }
    return render(request, 'mandala_circle/aboutMe.html', context)

def contact(request):
    data = cartData(request)

    cartItems = data['cartItems']

    context = {
        'cartItems': cartItems,
        'activate_contact': 'active'

    }
    return render(request, 'mandala_circle/contact.html', context)

# Send feedback for purchased item
@login_required
def give_feedback(request):
    data = cartData(request)

    cartItems = data['cartItems']

    form = FeedbackForm
    if request.method == "POST":
        form = FeedbackForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS, "Feedback sucessfully Sent")
            return redirect('/mandala_circle/contact')
        else:
            messages.add_message(request, messages.ERROR, "Unable to Send Feedback")
            return render(request, 'mandala_circle/giveFeedback.html', {'form_feedback': form})
    context = {
        'cartItems': cartItems,
        'form_feedback': FeedbackForm,
        'activate_contact': 'active'
    }
    return render(request, 'mandala_circle/giveFeedback.html', context)

#Display Art work
def art_gallery(request):
    data = cartData(request)

    cartItems = data['cartItems']

    context = {
        'cartItems': cartItems,
        'activate_gallery': 'active'
    }
    return render(request, 'mandala_circle/gallery.html', context)

#Request for commission art
@login_required
def shop_commission(request):
    form = CommissionForm
    data = cartData(request)

    cartItems = data['cartItems']
    if request.method == "POST":
        form = CommissionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS, "Query sucessfully Sent")
        else:
            messages.add_message(request, messages.ERROR, "Unable to Send")
            return render(request, 'mandala_circle/allCommission.html', {'form_commission': form})
    context = {
        'form_commission': CommissionForm,
        'cartItems': cartItems,
        'activate_commission': 'active'
    }
    return render(request, 'mandala_circle/allCommission.html', context)


# Original Artwork display from backend
@login_required
@user_only
def show_original(request):
    if request.user.is_authenticated:
        user = request.user
        order, created = Order.objects.get_or_create(user=user, complete=False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_total': 0, 'get_cart_items': 0}
        cartItems = order['get_cart_items']

    originals = Product.objects.all().order_by('id')
    context = {
        'originals': originals,
        'cartItems': cartItems,
        'activate_original': 'active'
    }
    return render(request, 'mandala_circle/getallOriginals.html', context)

#Product detail display function
def show_detail(request, original_id):
    data = cartData(request)
    cartItems = data['cartItems']
    originals = Product.objects.filter(id=original_id)

    context = {
        'cartItems': cartItems,
        'originals': originals,
        'activate_original': 'active'

    }
    return render(request, 'mandala_circle/productdetail.html', context)


@user_only
def show_gallery(request):
    if request.user.is_authenticated:
        user = request.user
        order, created = Order.objects.get_or_create(user=user, complete=False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_total': 0, 'get_cart_items': 0}
        cartItems = order['get_cart_items']

    gallery = Gallery.objects.all().order_by('id')
    context = {
        'gallery': gallery,
        'cartItems': cartItems,
        'activate_original': 'active'
    }
    return render(request, 'mandala_circle/gallery.html', context)

#Add to cart function
@login_required
def cart(request):
    data = cartData(request)

    cartItems = data['cartItems']
    order = data['order']
    items = data['items']

    context = {'activate_cart': 'active', 'items': items, 'order': order, 'cartItems': cartItems}
    return render(request, 'mandala_circle/cart.html', context)

#Add subtract product from cart
@login_required
def updateItem(request):
    data = json.loads(request.body)
    productId = data['productId']
    action = data['action']
    print('Action:', action)
    print('ProductId:', productId)

    user = request.user
    product = Product.objects.get(id=productId)
    order, created = Order.objects.get_or_create(user=user, complete=False)

    orderItem, created = OrderItem.objects.get_or_create(order=order, product=product)

    if action == 'add':
        orderItem.quantity = (orderItem.quantity + 1)
    elif action == 'remove':
        orderItem.quantity = (orderItem.quantity - 1)

    orderItem.save()

    if orderItem.quantity <= 0:
        orderItem.delete()

    return JsonResponse('Item was added', safe=False)

#Payment Procedure

@login_required
def checkout(request):
    data = cartData(request)

    cartItems = data['cartItems']
    order = data['order']
    items = data['items']

    context = {'activate_cart': 'active', 'items': items, 'order': order, 'cartItems': cartItems, }
    return render(request, 'mandala_circle/checkout.html', context)


@login_required
def processOrder(request):
    transaction_id = datetime.datetime.now().timestamp()
    data = json.loads(request.body)

    if request.user.is_authenticated:
        user = request.user
        order, created = Order.objects.get_or_create(user=user, complete=False)

        total = float(data['form']['total'])
        order.transaction_id = transaction_id

        if total == float(order.get_cart_total):
            order.complete = True
        order.save()

        if order.shipping == True:
            ShippingAddress.objects.create(
                user=user,
                order=order,
                address=data['shipping']['address'],
                city=data['shipping']['city'],
                state=data['shipping']['province'],
                zipcode=data['shipping']['zipcode'],

            )
    else:
        print("User is not logged in..")
    return JsonResponse('Payment submitted..', safe=False)


#Order history for User
@login_required
@user_only
def show_orders(request):
    data = cartData(request)

    cartItems = data['cartItems']
    items = OrderItem.objects.filter().order_by("id")
    context = {
        'activate_orders':'active',
        'items': items,
        'cartItems':cartItems,

    }
    return render(request, 'mandala_circle/orders.html', context)

#Deleting order history
@user_only
def delete_order(request, order_id):
    items = OrderItem.objects.get(id=order_id)
    items.delete()
    messages.add_message(request, messages.SUCCESS, "Order deleted successfully")
    return redirect('/mandala_circle/show_orders')


#Admin panel functions

#For displaying orders
@admin_only
def get_orders(request):
    items = OrderItem.objects.filter().order_by("id")
    context = {
        'items': items,
        'activate_orders': 'active'
    }
    return render(request, 'mandala_circle/get_orders.html', context)

#For updating orders
@admin_only
def Updateorders(request,id,order_status):
    item = OrderItem.objects.filter(id=id).update(delivered_status=order_status)
    return redirect('/mandala_circle/get_orders')

#Showing shipping detail
@admin_only
def get_shipping_detail(request):
    shipping = ShippingAddress.objects.filter().order_by("id")
    context = {
        'activate_orders': 'active',
        'shipping': shipping,
        'activate_shipping': 'active'
    }
    return render(request, 'mandala_circle/get_address.html', context)

#Display commission request
@admin_only
def get_commission(request):
    commission = Commission.objects.all().order_by('id')
    context = {
        'commission': commission,
        'activate_commission': 'active'
    }
    return render(request, 'admins/get_commission.html', context)

#Display Feedback from user
@admin_only
def get_feedback(request):
    feedback = Feedback.objects.all().order_by('id')
    context = {
        'feedback': feedback,
        'activate_contact': 'active'
    }
    return render(request, 'admins/get_feedback.html', context)


#Adding Art works
# Admin views
@admin_only
def original_form(request):
    if request.method == "POST":
        form = OriginalForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS, "Original Art added successfully")
            return redirect("/mandala_circle/get_original")

        else:
            messages.add_message(request, messages.ERROR, "Unable to add original")
            return render(request, 'mandala_circle/originalForm.html', {'form_original': form})

    context = {
        'form_original': OriginalForm,
        'activate_original': 'active'
    }
    return render(request, 'mandala_circle/originalForm.html', context)


#Display artwork in Admin panel
@admin_only
def get_original(request):
    originals = Product.objects.all().order_by('id')
    context = {
        'originals': originals,
        'activate_original': 'active'

    }
    return render(request, 'mandala_circle/get_original.html', context)


@admin_only
def delete_original(request, original_id):
    original = Product.objects.get(id=original_id)
    os.remove(original.product_image.path)
    original.delete()
    messages.add_message(request, messages.SUCCESS, "Product deleted successfully")
    return redirect('/mandala_circle/get_original')


@admin_only
def update_original(request, original_id):
    original = Product.objects.get(id=original_id)
    if request.FILES.get('product_image'):
        os.remove(original.product_image.path)
    if request.method == 'POST':
        form = OriginalForm(request.POST, request.FILES, instance=original)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS, 'Sucessfully updated')
            return redirect("/mandala_circle/get_original")
        else:
            messages.add_message(request, messages.ERROR, 'Unable to update')
            return render(request, 'mandala_circle/originalForm.html', {'form_original': form})

    context = {
        'form_original': OriginalForm(instance=original),
        'activate_original': 'active'
    }

    return render(request, 'mandala_circle/originalForm.html', context)

#For Adding Art in gallery
@admin_only
def gallery_form(request):
    if request.method == "POST":
        form = GalleryForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS, "Art added successfully")
            return redirect("/mandala_circle/get_gallery")

        else:
            messages.add_message(request, messages.ERROR, "Unable to add in gallery")
            return render(request, 'mandala_circle/galleryForm.html', {'form_gallery': form})

    context = {
        'form_gallery': GalleryForm,
        'activate_original': 'active'
    }
    return render(request, 'mandala_circle/galleryForm.html', context)


#Display gallery in Admin panel
@admin_only
def get_art(request):
    gallery = Gallery.objects.all().order_by('id')
    context = {
        'gallery': gallery,
        'activate_original': 'active'

    }
    return render(request, 'mandala_circle/get_gallery.html', context)

# Delete Art from gallery
@admin_only
def delete_galleryart(request, gallery_id):
    gallery = Gallery.objects.get(id=gallery_id)
    os.remove(gallery.image.path)
    gallery.delete()
    messages.add_message(request, messages.SUCCESS, "Product deleted successfully")
    return redirect('/mandala_circle/get_gallery')

