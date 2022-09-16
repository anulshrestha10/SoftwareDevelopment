from django.urls import path
from .import views

urlpatterns = [
    # Userpage urls
    path ('aboutMe',views.about_me,name="about"),
    path ('contact',views.contact),
    path ('giveFeedback',views.give_feedback),
    path ('get_feedback',views.get_feedback),
    path ('show_original',views.show_original),
    path ('show_gallery',views.show_gallery),
    path ('allCommission',views.shop_commission, name="com"),
    path ('get_commission',views.get_commission),
    path ('privacyPolicy',views.privacy_policy),
    path ('refundPolicy',views.refund_policy),
    path ('termCondition',views.term_condition),
    path ('learnMandala',views.learn_mandala),
    path ('show_original/<int:original_id>',views.show_detail),
    path('cart/', views.cart, name="cart"),
    path('checkout/', views.checkout, name="checkout"),
    path('update_item/', views.updateItem, name="update_item"),
    path('process_order/', views.processOrder, name="process_order"),
    path('show_orders/', views.show_orders),
    path('delete_order/<int:order_id>', views.delete_order),
    path ('get_orders/',views.get_orders),
    path('update_status/<id>/<order_status>', views.Updateorders),
    path('get_address/',views.get_shipping_detail),

    # Admins Page urls
    #Add products
    path ('originalForm',views.original_form),
    path ('get_original',views.get_original),
    path ('delete_original/<int:original_id>', views.delete_original),
    path ('update_original/<int:original_id>', views.update_original),

    #Add Art in Gallery
    path('galleryForm', views.gallery_form),
    path('get_gallery', views.get_art),
    path('delete_galleryart/<int:gallery_id>', views.delete_galleryart),



]