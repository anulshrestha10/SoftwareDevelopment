from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .forms import LoginForm, CreateUserForm, ProfileForm
from accounts.auth import unauthenticated_user, admin_only, user_only
from django.contrib.auth.decorators import login_required
from .models import Profile
from mandala_circle.models import Order
from mandala_circle.utils import cartData
import os


@user_only
def homepage(request):
    data = cartData(request)

    cartItems = data['cartItems']
    context = {
        'cartItems':cartItems,
        'activate_home': 'active'
    }
    return render(request, 'accounts/homepage.html', context)


@unauthenticated_user
def register_user(request):
    if request.method == "POST":
        form = CreateUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            Profile.objects.create(user=user, username=user.username, email=user.email)
            messages.add_message(request, messages.SUCCESS, 'User registered successfull')
            return redirect('/login')
        else:
            messages.add_message(request, messages.ERROR, 'Something is wrong')
            return render(request, 'accounts/register.html', {'form_user': form})
    context = {
        'form_user': CreateUserForm,
        'activate_register': 'active'
    }
    return render(request, 'accounts/register.html', context)


@unauthenticated_user
def login_user(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            user = authenticate(request, username=data['username'], password=data['password'])
            print(user)
            if user is not None:
                if user.is_staff:
                    login(request, user)
                    return redirect('/admins/dashboard')
                elif not user.is_staff:
                    login(request, user)
                    return redirect('/')
            else:
                messages.add_message(request, messages.ERROR, 'User not registered')
                return render(request, 'accounts/login.html', {'form_login': form})
    context = {
        'form_login': LoginForm,
        'activate_login': 'active'
    }
    return render(request, 'accounts/login.html', context)


@login_required
def logout_user(request):
    logout(request)
    return redirect('/login')

@login_required
@admin_only
def get_users(request):
    users = User.objects.filter(is_staff=0).order_by('-id')
    context = {
        'users':users
    }
    return render(request, 'accounts/users.html', context)


@login_required
@admin_only
def get_admins(request):
    admins = User.objects.filter(is_staff=1).order_by('-id')
    context = {
        'admins':admins
    }
    return render(request, 'accounts/admins.html', context)


@login_required
@admin_only
def add_users(request):
    return render(request, 'accounts/users.html')

@login_required
@admin_only
def add_admin(request):
    if request.method == 'POST':
        form=CreateUserForm(request.POST)
        if form.is_valid():
            username=form.cleaned_data.get('username')
            email = form.cleaned_data.get('email')
            user = User.objects.create_user(username=username,email=email)
            user.is_staff=True
            user.save()

            return redirect('/admins/admins')
        else:
            messages.add_message(request,messages.ERROR,'Sorry! Something went wrong')
            return render(request,'accounts/add_admins.html',{'form_admin':form})
    context = {
        'form':CreateUserForm

    }
    return render(request, 'accounts/add_admins.html',context)

@admin_only
def delete_user(request, user_id):
    user = User.objects.get(id=user_id)
    user.delete()
    messages.add_message(request, messages.SUCCESS, "User deleted successfully")
    return redirect('/admins/users')

@admin_only
def delete_admin(request, user_id):
    user = User.objects.get(id=user_id)
    user.delete()
    messages.add_message(request, messages.SUCCESS, "Admin deleted successfully")
    return redirect('/admins/admins')

@login_required
@admin_only
def promote_user(request,user_id):
    user = User.objects.get(id=user_id)
    user.is_staff=True
    user.save()
    messages.add_message(request, messages.SUCCESS, 'User promoted to admin')
    return redirect('/admins/admins')

@login_required
@admin_only
def demote_user(request,user_id):
    user = User.objects.get(id=user_id)
    user.is_staff=False
    user.save()
    messages.add_message(request, messages.SUCCESS, 'Admin demoted to user')
    return redirect('/admins/users')

@user_only
def profile(request):
    data = cartData(request)

    cartItems = data['cartItems']
    profile = request.user.profile
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.add_message(request, messages.SUCCESS, 'Profile Updated Successfully')
            return redirect('/profile')
    context = {
        'cartItems':cartItems,
        'form': ProfileForm(instance=profile)
    }
    return render(request, 'accounts/profile.html', context)


