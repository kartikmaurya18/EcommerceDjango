from django.shortcuts import render, redirect
from ecommerceapp.models import Contact, Product, OrderUpdate, Orders
from math import ceil
from django.contrib import messages
from django.conf import settings
from ecommerceapp import keys
import json
from django.views.decorators.csrf import csrf_exempt
from PayTm import Checksum

# Paytm merchant key
MK = keys.MK

# Homepage
def index(request):
    allProds = []
    catprods = Product.objects.values('category', 'id')
    cats = {item['category'] for item in catprods}
    for cat in cats:
        prod = Product.objects.filter(category=cat)
        n = len(prod)
        nSlides = n // 4 + ceil((n / 4) - (n // 4))
        allProds.append([prod, range(1, nSlides), nSlides])
    
    params = {'allProds': allProds}
    return render(request, "index.html", params)

# Contact Us Page
def contact(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        desc = request.POST.get("desc")
        pnumber = request.POST.get("pnumber")
        myquery = Contact(name=name, email=email, desc=desc, pnumber=pnumber)
        myquery.save()
        messages.info(request, "We will get back to you soon.")
    return render(request, "contact.html")

# About Us Page
def about(request):
    return render(request, "about.html")

# Checkout Page
  # Ensure you have the correct import or definition for your keys

def checkout(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Please log in and try again.")
        return redirect('/auth/login')

    if request.method == "POST":
        # Collect order details
        items_json = request.POST.get('itemsJson', '')
        name = request.POST.get('name', '')
        amount = request.POST.get('amt', '')
        email = request.POST.get('email', '')
        address1 = request.POST.get('address1', '')
        address2 = request.POST.get('address2', '')
        city = request.POST.get('city', '')
        state = request.POST.get('state', '')
        zip_code = request.POST.get('zip_code', '')
        phone = request.POST.get('phone', '')

        if not amount:
            messages.error(request, "Amount is required.")
            return redirect('auth/checkout/')  # Redirect back to the checkout page with an error

        # Save the order in the database
        order = Orders(
            items_json=items_json, name=name, amount=amount, email=email, 
            address1=address1, address2=address2, city=city, state=state, 
            zip_code=zip_code, phone=phone
        )
        order.save()
        
        # Update order status
        update = OrderUpdate(order_id=order.order_id, update_desc="Order has been placed.")
        update.save()
        
        # Prepare Paytm parameters
        oid = f"{order.order_id}ShopyCart"
        param_dict = {
            'MID': keys.MID,
            'ORDER_ID': oid,
            'TXN_AMOUNT': str(amount),
            'CUST_ID': email,
            'INDUSTRY_TYPE_ID': 'Retail',
            'WEBSITE': 'WEBSTAGING',  # Use 'DEFAULT' for production
            'CHANNEL_ID': 'WEB',
            'CALLBACK_URL': 'http://127.0.0.1:8000/handlerequest/',
        }
        
        # Generate checksum
        param_dict['CHECKSUMHASH'] = Checksum.generate_checksum(param_dict, keys.MK)
        
        return render(request, 'paytm.html', {'param_dict': param_dict})

    return render(request, 'checkout.html')

@csrf_exempt
def handlerequest(request):
    # Paytm will send POST request here
    form = request.POST
    response_dict = {key: form[key] for key in form.keys()}

    # Verify the checksum
    checksum = response_dict.get('CHECKSUMHASH', '')
    verify = Checksum.verify_checksum(response_dict, keys.MK, checksum)

    if verify:
        if response_dict.get('RESPCODE') == '01':
            # Order successful
            print('Order successful')
            order_id = response_dict['ORDERID'].replace("ShopyCart", "")
            Orders.objects.filter(order_id=order_id).update(
                oid=response_dict['ORDERID'],
                amountpaid=response_dict['TXNAMOUNT'],
                paymentstatus="PAID"
            )
            messages.success(request, "Payment successful!")
        else:
            # Order failed
            print(f"Order failed due to {response_dict.get('RESPMSG')}")
            messages.error(request, f"Payment failed: {response_dict.get('RESPMSG')}")
    else:
        print("Checksum verification failed")
        messages.error(request, "Payment verification failed")

    return render(request, 'paymentstatus.html', {'response': response_dict})


# User Profile
def profile(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login & Try Again")
        return redirect('/auth/login')

    currentuser = request.user.username
    orders = Orders.objects.filter(email=currentuser)
    
    context = {"items": orders}
    return render(request, "profile.html", context)

from django.shortcuts import render

def order(request):
    # Your order processing logic here
    return render(request, 'order.html')

