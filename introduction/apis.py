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
        # The lab's target endpoint is CSRF protected like every other view, so
        # this server side test bench has to authenticate its own unsafe
        # requests: send the CSRF cookie plus the matching X-CSRFToken header,
        # which is Django's documented pattern for non-browser clients.
        csrf_token = get_token(request)
        # CWE-915: the submitted lab modules replace files on disk, so both
        # fields are validated at this boundary (present, bounded, control
        # character free and syntactically valid Python) and rejected with a
        # 400 before anything is written.
        try:
            log_code = safe_python_source(request.POST.get('log_code'), field='log_code')
            api_code = safe_python_source(request.POST.get('api_code'), field='api_code')
        except InvalidStoredTextError as error:
            return JsonResponse({"message": str(error)}, status = 400)
        dirname = os.path.dirname(__file__)
        log_filename = os.path.join(dirname, "playground/A9/main.py")
        api_filename = os.path.join(dirname, "playground/A9/api.py")
        f = open(log_filename,"w")
        f.write(log_code)
        f.close()
        f = open(api_filename,"w")
        f.write(api_code)
        f.close()
        # Clearing the log file before starting the test
        f = open('test.log', 'w')
        f.write("")
        f.close()
        url = "http://127.0.0.1:8000/2021/discussion/A9/target"
        payload={'csrfmiddlewaretoken': csrf_token }
        csrf_cookies = {settings.CSRF_COOKIE_NAME: csrf_token}
        csrf_headers = {'X-CSRFToken': csrf_token}
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

def A6_disscussion_api_2(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)
    # CWE-915: only bounded, control character free, syntactically valid Python
    # is allowed to replace the lab module on disk.
    try:
        code = safe_python_source(request.POST.get('code'))
    except InvalidStoredTextError as error:
        return JsonResponse({"message": str(error)}, status = 400)
    try:
        dirname = os.path.dirname(__file__)
        filename = os.path.join(dirname, "playground/A6/utility.py")
        f = open(filename,"w")
        f.write(code)
        f.close()
    except:
        return JsonResponse({"message":"missing code"},status = 400)
    return JsonResponse({"message":"success"},status = 200)