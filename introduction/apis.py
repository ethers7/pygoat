import time

import requests
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.shortcuts import redirect

from introduction.playground.A6.utility import check_vuln
from introduction.playground.A9.main import Log
from introduction.playground.ssrf import main

from .utility import *
from .views import authentication_decorator


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


# @authentication_decorator
def log_function_checker(request):
    if request.method == 'POST':
        csrf_token = request.POST.get("csrfmiddlewaretoken")
        # The submitted code is request data that ends up in files on disk, so it
        # is neutralised and validated before the write (CWE-93): safe_lab_source()
        # folds CR/CRLF to LF, drops the remaining control characters, bounds the
        # size and requires parseable Python, and write_lab_file() confines the
        # destination to the lab's own playground directory. The raw request value
        # is never written.
        try:
            log_code = safe_lab_source(request.POST.get('log_code'))
            api_code = safe_lab_source(request.POST.get('api_code'))
            write_lab_file("playground/A9/main.py", log_code)
            write_lab_file("playground/A9/api.py", api_code)
        except ValueError as rejected:
            return JsonResponse(
                {"message": "invalid code: %s" % rejected, "logs": []}, status = 400)
        except OSError:
            return JsonResponse(
                {"message": "could not save the code", "logs": []}, status = 400)
        # Clearing the log file before starting the test
        f = open('test.log', 'w')
        f.write("")
        f.close()
        url = "http://127.0.0.1:8000/2021/discussion/A9/target"
        # The lab target is CSRF protected like every other state changing view
        # (CWE-352), so these unsafe-method probes must carry this session's CSRF
        # credentials: the csrftoken cookie plus the matching token (posted as
        # csrfmiddlewaretoken, and as X-CSRFToken for the methods that cannot
        # carry form data). Without them CsrfViewMiddleware rejects the probe.
        csrf_cookie = request.COOKIES.get(settings.CSRF_COOKIE_NAME, "")
        csrf_token = csrf_token or csrf_cookie
        payload={'csrfmiddlewaretoken': csrf_token }
        csrf_cookies = {settings.CSRF_COOKIE_NAME: csrf_cookie}
        csrf_headers = {"X-CSRFToken": csrf_token}
        requests.request("GET", url)
        requests.request("POST", url, data=payload, cookies=csrf_cookies, headers=csrf_headers)
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

def A6_disscussion_api_2(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)
    # Same guards as the A9 checker: the request supplied code is neutralised and
    # parsed before it replaces the lab module, and write_lab_file() keeps the
    # destination inside the allowlisted playground directory (CWE-93).
    try:
        code = safe_lab_source(request.POST.get('code'))
        write_lab_file("playground/A6/utility.py", code)
    except ValueError as rejected:
        return JsonResponse({"message":"invalid code: %s" % rejected},status = 400)
    except OSError:
        return JsonResponse({"message":"could not save the code"},status = 400)
    return JsonResponse({"message":"success"},status = 200)