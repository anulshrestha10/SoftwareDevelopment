from django.shortcuts import render,redirect
from accounts.auth import unauthenticated_user,admin_only,user_only
from django.contrib.auth.decorators import login_required
from mandala_circle.models import *
import os

@admin_only
def dashboard(request):
    artwork = Product.objects.all()
    art_count = artwork.count()
    gallery = Gallery.objects.all()
    gallery_count = gallery.count()
    commission = Commission.objects.all()
    commission_count = commission.count()
    order = OrderItem.objects.all()
    order_count = order.count()
    feed = Feedback.objects.all()
    feed_count = feed.count()
    users = User.objects.all()
    user_count = users.filter(is_staff=0).count()
    admin_count = users.filter(is_staff=1).count()
    context = {
        'activate_dashboard':'active',
        'artwork': art_count,
        'gallery':gallery_count,
        'commission': commission_count,
        'order':order_count,
        'feed': feed_count,
        'user': user_count,
        'admin': admin_count
    }

    return render(request, 'admins/dashboard.html', context)


@admin_only
def admin(request):
    context = {
        'activate_admin': 'active'
    }
    return render(request,'admins/adminpage.html',context)



