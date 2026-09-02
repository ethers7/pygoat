import datetime
import re
import subprocess

import jwt
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt

from pygoat.settings import CSRF_LAB_JWT_KEY

from .models import CSRF_user_tbl, verify_lab_password
from .utility import (UnsafeExpressionError, safe_arithmetic_eval,
                      safe_host_target)
from .views import authentication_decorator

# import os

## Mitre top1 | CWE:787

# target zone
FLAG = "NOT_SUPPOSED_TO_BE_ACCESSED"

# target zone end


@authentication_decorator
def mitre_top1(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top1.html')

@authentication_decorator
def mitre_top2(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top2.html')

@authentication_decorator
def mitre_top3(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top3.html')
        
@authentication_decorator
def mitre_top4(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top4.html')
        
@authentication_decorator
def mitre_top5(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top5.html')
        
@authentication_decorator
def mitre_top6(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top6.html')
        
@authentication_decorator
def mitre_top7(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top7.html')
        
@authentication_decorator
def mitre_top8(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top8.html')
        
@authentication_decorator
def mitre_top9(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top9.html')
        
@authentication_decorator
def mitre_top10(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top10.html')
        
@authentication_decorator
def mitre_top11(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top11.html')
        
@authentication_decorator
def mitre_top12(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top12.html')
        
@authentication_decorator
def mitre_top13(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top13.html')
        
@authentication_decorator
def mitre_top14(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top14.html')

@authentication_decorator
def mitre_top15(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top15.html')

@authentication_decorator
def mitre_top16(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top16.html')

@authentication_decorator
def mitre_top17(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top17.html')

@authentication_decorator
def mitre_top18(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top18.html')

@authentication_decorator
def mitre_top19(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top19.html')


@authentication_decorator
def mitre_top20(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top20.html')


@authentication_decorator
def mitre_top21(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top21.html')


@authentication_decorator
def mitre_top22(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top22.html')


@authentication_decorator
def mitre_top23(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top23.html')


@authentication_decorator
def mitre_top24(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top24.html')

@authentication_decorator
def mitre_top25(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top25.html')

@authentication_decorator
def csrf_lab_login(request):
    if request.method == 'GET':
        return render(request, 'mitre/csrf_lab_login.html')
    elif request.method == 'POST':
        password = request.POST.get('password')
        username = request.POST.get('username')
        # CWE-327: the submitted password is verified against the stored PBKDF2
        # hash with Django's configured hashers instead of being matched as an
        # unsalted MD5 digest.
        user = CSRF_user_tbl.objects.filter(username=username).first()
        if user is not None and verify_lab_password(password, user.password):
            payload ={
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
                'iat': datetime.datetime.utcnow()
            }
            cookie = jwt.encode(payload, CSRF_LAB_JWT_KEY, algorithm='HS256')
            response = redirect("/mitre/9/lab/transaction")
            response.set_cookie('auth_cookiee', cookie)
            return response
        else :
            return redirect('/mitre/9/lab/login')

@authentication_decorator
@csrf_exempt
def csrf_transfer_monei(request):
    if request.method == 'GET':
        try:
            cookie = request.COOKIES['auth_cookiee']
            payload = jwt.decode(cookie, CSRF_LAB_JWT_KEY, algorithms=['HS256'])
            username = payload['username']
            User = CSRF_user_tbl.objects.filter(username=username)
            if not User:
                redirect('/mitre/9/lab/login')
            return render(request, 'mitre/csrf_dashboard.html', {'balance': User[0].balance})
        except:
            return redirect('/mitre/9/lab/login')

def csrf_transfer_monei_api(request,recipent,amount):
    if request.method == "GET":
        cookie = request.COOKIES['auth_cookiee']
        payload = jwt.decode(cookie, CSRF_LAB_JWT_KEY, algorithms=['HS256'])
        username = payload['username']
        User = CSRF_user_tbl.objects.filter(username=username)
        if not User:
            return redirect('/mitre/9/lab/login')
        if int(amount) > 0:
            if int(amount) <= User[0].balance:
                recipent = CSRF_user_tbl.objects.filter(username=recipent)
                if recipent:
                    recipent = recipent[0]
                    recipent.balance = recipent.balance + int(amount)
                    recipent.save()
                    User[0].balance = User[0].balance - int(amount)
                    User[0].save()
        return redirect('/mitre/9/lab/transaction') 
    else:
        return redirect ('/mitre/9/lab/transaction')


# @authentication_decorator
@csrf_exempt
def mitre_lab_25_api(request):
    if request.method == "POST":
        expression = request.POST.get('expression')
        # Calculator lab: the submitted expression is still evaluated, but only
        # as bounded arithmetic. Request data never reaches eval/exec (CWE-95).
        try:
            result = safe_arithmetic_eval(expression)
        except UnsafeExpressionError as error:
            return JsonResponse(
                {'result': 'Invalid expression: {}'.format(error)}, status=400
            )
        return JsonResponse({'result': result})
    else:
        return redirect('/mitre/25/lab/')


@authentication_decorator
def mitre_lab_25(request):
    return render(request, 'mitre/mitre_lab_25.html')

@authentication_decorator
def mitre_lab_17(request):
    return render(request, 'mitre/mitre_lab_17.html')

ALLOWED_COMMANDS = frozenset({'nmap'})


def command_out(command):
    """Run an allowlisted command given as an argv list, never through a shell."""
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError('command must be a non-empty argument list')
    argv = [str(arg) for arg in command]
    if argv[0] not in ALLOWED_COMMANDS:
        raise ValueError('command not allowed')
    process = subprocess.Popen(argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()
    

@csrf_exempt
def mitre_lab_17_api(request):
    if request.method == "POST":
        ip = safe_host_target(request.POST.get('ip'), allow_networks=True)
        if ip is None:
            return JsonResponse(
                {'raw_res': '', 'raw_err': 'Invalid scan target', 'ports': []},
                status=400)
        res, err = command_out(['nmap', ip])
        res = res.decode()
        err = err.decode()
        pattern = "STATE SERVICE.*\\n\\n"
        ports = re.findall(pattern, res,re.DOTALL)[0][14:-2].split('\n')
        return JsonResponse({'raw_res': str(res), 'raw_err': str(err), 'ports': ports})