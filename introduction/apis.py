import time

import requests
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect

from introduction.playground.A6.utility import check_vuln
from introduction.playground.A9.main import Log
from introduction.playground.ssrf import main

from .utility import *
from .utility import (MAX_LAB_CODE_BYTES, SubmittedContentTooLargeError,
                      UnsafeWritePathError, resolve_inside_directory,
                      validate_submitted_text, write_text_atomically)
from .views import authentication_decorator

# Fixed destinations for the playground code editors. They are computed from
# this module's location, never from request data, and every write goes through
# resolve_inside_directory() so the file stays in its own playground directory.
PLAYGROUND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "playground")
A6_PLAYGROUND_DIR = os.path.join(PLAYGROUND_DIR, "A6")
A9_PLAYGROUND_DIR = os.path.join(PLAYGROUND_DIR, "A9")


# steps -->
# 1. covert input code to corrosponding code and write in file
# 2. extract inputs form 2nd code 
# 3. Run the code 
# 4. get the result
def ssrf_code_checker(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            python_code = request.POST['python_code']
            html_code = request.POST['html_code']
            if not (ssrf_code_converter(python_code)):
                return JsonResponse({"status": "error", "message": "Invalid code"})
            test_bench1 = ssrf_html_input_extractor(html_code)
            
            if (len(test_bench1) >4):
                return JsonResponse({'message':'too many inputs in Html\n Try again'},status = 400)
            test_bench2 = ['secret.txt']
            correct_output1 = [{"blog": "blog1-passed"}, {"blog": "blog2-passed"}, {"blog": "blog3-passed"}, {"blog": "blog4-passed"}]
            outputs = []
            for inputs in test_bench1:
                outputs.append(main.ssrf_lab(inputs))
            if outputs == correct_output1:
                outputs = []
            else:
                return JsonResponse({'message':'Testbench failed, Code is not working\n Try again'},status = 200)

            correct_output2 = [{"blog": "No blog found"}]
            for inputs in test_bench2:
                outputs.append(main.ssrf_lab(inputs))
            if outputs == correct_output2:
                return JsonResponse({'message':'Congratulation, you have written a secure code.', 'passed':1}, status = 200)
            
            return JsonResponse({'message':'Test bench passed but the code is not secure'}, status = 200,safe = False)
        else:
            return JsonResponse({'message':'method not allowed'},status = 405)
    else:
        return JsonResponse({'message':'UnAuthenticated User'},status = 401)

# Insufficient Logging & Monitoring


# This test bench stores the code a student submits in the A9 playground, so it
# is restricted to an authenticated session like the A9 discussion page that
# serves it. The caller is a fetch() in a9.js, so it answers 401 as JSON the way
# ssrf_code_checker above does instead of using views.authentication_decorator,
# which answers with a redirect to the login page.
def log_function_checker(request):
    if not request.user.is_authenticated:
        return JsonResponse({'message': 'UnAuthenticated User'}, status=401)
    if request.method == 'POST':
        # Bound the submitted code and pin both destinations to the A9
        # playground directory before opening anything: the request can only
        # decide the file *contents*, never the path or its size.
        try:
            log_code = validate_submitted_text(request.POST.get('log_code'),
                                               MAX_LAB_CODE_BYTES)
            api_code = validate_submitted_text(request.POST.get('api_code'),
                                               MAX_LAB_CODE_BYTES)
            log_filename = resolve_inside_directory(A9_PLAYGROUND_DIR, "main.py")
            api_filename = resolve_inside_directory(A9_PLAYGROUND_DIR, "api.py")
        except (SubmittedContentTooLargeError, UnsafeWritePathError) as exc:
            return JsonResponse({"message": str(exc)}, status=400)
        try:
            write_text_atomically(log_filename, log_code)
            write_text_atomically(api_filename, api_code)
        except OSError:
            return JsonResponse({"message":"could not save code"},status = 500)
        # Clearing the log file before starting the test
        f = open('test.log', 'w')
        f.write("")
        f.close()
        url = "http://127.0.0.1:8000/2021/discussion/A9/target"
        # The target route is CSRF protected like every other route, so this
        # server side test bench has to present a valid token pair instead of
        # relying on an exemption: Django matches the token sent with the
        # request against the secret carried by the CSRF cookie. Forward this
        # request's own CSRF cookie together with a token derived from it, which
        # is exactly what a browser would send.
        target_csrf_token = get_token(request)
        csrf_cookies = {settings.CSRF_COOKIE_NAME: request.COOKIES.get(
            settings.CSRF_COOKIE_NAME, target_csrf_token)}
        csrf_headers = {"X-CSRFToken": target_csrf_token}
        payload={'csrfmiddlewaretoken': target_csrf_token }
        requests.request("GET", url)
        requests.request("POST", url, cookies=csrf_cookies, headers=csrf_headers)
        requests.request("PATCH", url, data=payload, cookies=csrf_cookies, headers=csrf_headers)
        requests.request("DELETE", url, cookies=csrf_cookies, headers=csrf_headers)
        f = open('test.log', 'r')
        lines = f.readlines()
        f.close()
        return JsonResponse({"message":"success", "logs": lines},status = 200)
    else:
        return JsonResponse({"message":"method not allowed"},status = 405)

#a7 codechecking api
def A7_disscussion_api(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)

    try:
        code = request.POST.get('code')
    except:
        return JsonResponse({"message":"missing code"},status = 400)

    search_snipet = "AF_session_id.objects.get(sesssion_id = cookie).delete()"
    search_snipet2 = "AF_session_id.objects.get(sesssion_id=cookie).delete()"

    if (search_snipet in code) or (search_snipet2 in code):
        return JsonResponse({"message":"success"},status = 200)

    return JsonResponse({"message":"failure"},status = 400)

#a6 codechecking api
def A6_disscussion_api(request):
    test_bench = ["Pillow==8.0.0","PyJWT==2.4.0","requests==2.28.0","Django==4.0.4"]
    
    try:
        result = check_vuln(test_bench)
        print(len(result))
        if result:
            return JsonResponse({"message":"success","vulns":result},status = 200)
        return JsonResponse({"message":"failure"},status = 400)
    except Exception as e:
        return JsonResponse({"message":"failure"},status = 400)

# Stores the code a student submits in the A6 playground, so - like the A6
# discussion page that serves it - it needs an authenticated session.
def A6_disscussion_api_2(request):
    if not request.user.is_authenticated:
        return JsonResponse({'message': 'UnAuthenticated User'}, status=401)
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)
    # Same guardrails as the A9 test bench: the size of the snippet is bounded
    # and the destination is pinned to the A6 playground directory, so request
    # data only ever decides the file contents.
    try:
        code = validate_submitted_text(request.POST.get('code'), MAX_LAB_CODE_BYTES)
        filename = resolve_inside_directory(A6_PLAYGROUND_DIR, "utility.py")
    except (SubmittedContentTooLargeError, UnsafeWritePathError) as exc:
        return JsonResponse({"message": str(exc)}, status=400)
    try:
        write_text_atomically(filename, code)
    except OSError:
        return JsonResponse({"message":"could not save code"},status = 500)
    return JsonResponse({"message":"success"},status = 200)