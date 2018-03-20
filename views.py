from __future__ import unicode_literals
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth.models import User
from django.contrib import messages
from models import User
# from django.contrib.auth import login as auth_login
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.core.urlresolvers import reverse
from django import forms
from .models import Profile

from .forms import SignUpForm


###################################

from collections import OrderedDict

from django import forms
from django.core.mail import EmailMultiAlternatives
from django.forms.utils import flatatt
from django.template import loader
from django.utils.encoding import force_bytes
from django.utils.html import format_html, format_html_join
from django.utils.http import urlsafe_base64_encode
from django.utils.safestring import mark_safe
from django.utils.text import capfirst
from django.utils.translation import ugettext, ugettext_lazy as _

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.hashers import UNUSABLE_PASSWORD_PREFIX, identify_hasher
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site

from django.core.urlresolvers import resolve




"""
Method:             dashboard
Created Date:       01-03-2018
Purpose:            Show user's dashboard
Params:             null
Return:             null
"""
def dashboard(request):
    current_url = ''
    current_url = resolve(request.path_info).url_name
    print "path "+current_url
    current_user = request.user
    template_name = 'dashboard.html'
    try:
       queryset = Profile.objects.get(user_id=current_user.id)
    except Profile.DoesNotExist:
       queryset = None

    context = {
        "profile": queryset
    }
    if request.user.is_authenticated():
        if current_url is not None:
            # return render(request, 'dashboard.html')
            return render(request, template_name, context)
        else:
            return render(request, 'dashboard.html')
    else :
        return redirect("/")

# logout authentication
def logout(request):
    try:
        just_logged_out = request.session.get('just_logged_out',False)
        return redirect("/")
    except:
        just_logged_out = False

"""
Method:             signup
Created Date:       02-03-2018
Purpose:            User signup
Params:             [user form data]
Return:             user hash []
"""
def signup(request):
    # return HttpResponse("Page is coming Soon")
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()
            # load the profile instance created by the signal
            user.fullname = form.cleaned_data["fullname"]
            user.save()
            current_site = get_current_site(request) # Sending email to user
            subject = 'Welcome Email'
            message = render_to_string('welcome_email_template.html', {
                'user': user,
            })
            user.email_user(subject, message)
            # Checking SignUp
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=user.username, password=raw_password)
            login(request, user) # user login and redirect to dashboard
            messages.success(request, 'You are Successfully Registered!')
            return redirect('dashboard')
    else:
        form = SignUpForm()
    return render(request, 'index.html', {'form': form})

"""
Method:             userlogin
Created Date:       02-03-2018
Purpose:            user singin
Params:             [email, password]
Return:             user hash []
"""
def userlogin(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        try: # Checkin the User exist in the database
           new_user = User.objects.get(email = username)
        except User.DoesNotExist:
           new_user = None

        if new_user is not None:
            user = authenticate(username = new_user.username, password = password)
            if user is not None:
                login(request, user)
                messages.success(request, 'You are Successfully login!')
                return HttpResponseRedirect('/dashboard')

        # Render to login Page
        messages.warning(request, 'Please enter the correct details.')
        form = SignUpForm()
        return render(request, 'index.html', {'form': form})
    else:
        form = SignUpForm()
    return render(request, 'index.html', {'form': form})

"""
Method:             forgotpassword
Created Date:       02-03-2018
Purpose:            User forgot password and send email to rest password
Params:             [email]
Return:             user hash []
"""
def forgotpassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try: # Getting Users
            user = User.objects.get(email=email)
            if (not user):
                form = SignUpForm()
                return render(request, 'index.html', {'form': form})
            else:
                messages.success(request, 'mail has been sent') # Sending Email
                subject = 'Forgot Password Email'
                message = render_to_string('forgot_password_template.html', {
                    'user': user,
                })
                user.email_user(subject, message)
                form = SignUpForm()
            return render(request, 'index.html', {'form': form})
        except User.DoesNotExist:
            user = None
            messages.warning(request, 'No user found with this email')  # <-
            form = SignUpForm()
            return render(request, 'index.html', {'form': form})
        # return render(request, 'signup.html')
    else:
        form = SignUpForm()
    return render(request, 'index.html', {'form': form})

"""
Method:             password_reset
Created Date:       19-03-2018
Purpose:            User forgot password and send email to rest password
Params:             [email]
Return:             user hash []
"""
@csrf_protect
def password_reset(request, is_admin_site=False,
                   template_name='registration/password_reset_form.html',
                   email_template_name='registration/password_reset_email.html',
                   subject_template_name='registration/password_reset_subject.txt',
                   password_reset_form=PasswordResetForm,
                   token_generator=default_token_generator,
                   post_reset_redirect=None,
                   from_email=None,
                   current_app=None,
                   extra_context=None,
                   html_email_template_name=None):
    if post_reset_redirect is None:
        post_reset_redirect = reverse('password_reset_done')
    else:
        post_reset_redirect = resolve_url(post_reset_redirect)
    if request.method == "POST":
        form = password_reset_form(request.POST)
        if form.is_valid():
            opts = {
                'use_https': request.is_secure(),
                'token_generator': token_generator,
                'from_email': from_email,
                'email_template_name': email_template_name,
                'subject_template_name': subject_template_name,
                'request': request,
                'html_email_template_name': html_email_template_name,
            }
            if is_admin_site:
                warnings.warn(
                    "The is_admin_site argument to "
                    "django.contrib.auth.views.password_reset() is deprecated "
                    "and will be removed in Django 2.0.",
                    RemovedInDjango20Warning, 3
                )
                opts = dict(opts, domain_override=request.get_host())
            form.save(**opts)
            # return HttpResponseRedirect(post_reset_redirect)
            messages.success(request, 'We\'ve emailed you instructions for setting your password, if an account exists with the email you entered. You should receive them shortly.')
            form = SignUpForm()
            return render(request, 'index.html', {'form': form})
    else:
        form = password_reset_form()
    context = {
        'form': form,
        'title': _('Password reset'),
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,current_app=current_app)
