import time

import requests
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.shortcuts import redirect

from introduction.playground.A6.utility import check_vuln
from introduction.playground.A9.main import Log
from introduction.playground.ssrf import main

from .utility import *
from .utility import LabCodeRejected, validate_lab_code, write_lab_code
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


# This coding ground replaces two modules of the running app with the code the
# student submitted, so it must never be reachable anonymously: the decorator
# below used to be commented out, which made the write (and the import of that
# code by the app) available to any unauthenticated caller.
@authentication_decorator
def log_function_checker(request):
    if request.method == 'POST':
        csrf_token = request.POST.get("csrfmiddlewaretoken")
        log_code = request.POST.get('log_code')
        api_code = request.POST.get('api_code')
        # write_lab_code() picks the destination itself from a fixed allowlist,
        # caps the size and refuses code that does not parse; both submissions
        # are validated before either module is replaced, and each replacement
        # is atomic. Running the student's code is still the exercise - that is
        # not made safe here, see introduction/utility.py.
        try:
            validate_lab_code(log_code)
            validate_lab_code(api_code)
            write_lab_code('A9_log', log_code)
            write_lab_code('A9_api', api_code)
        except LabCodeRejected as rejected:
            return JsonResponse({"message": "invalid code: {}".format(rejected)}, status=400)
        except OSError:
            return JsonResponse({"message": "code could not be saved"}, status=500)
        # Clearing the log file before starting the test
        f = open('test.log', 'w')
        f.write("")
        f.close()
        url = "http://127.0.0.1:8000/2021/discussion/A9/target"
        # The target view is CSRF protected like every other view, so these
        # server-side probe requests forward the caller's own token (csrftoken
        # cookie + X-CSRFToken header) instead of exempting the view.
        csrf_cookie = request.COOKIES.get('csrftoken', '')
        csrf_token = csrf_token or csrf_cookie
        cookies = {'csrftoken': csrf_cookie} if csrf_cookie else {}
        headers = {'X-CSRFToken': csrf_token}
        payload={'csrfmiddlewaretoken': csrf_token }
        requests.request("GET", url)
        requests.request("POST", url, headers=headers, cookies=cookies)
        requests.request("PATCH", url, data=payload, headers=headers, cookies=cookies)
        requests.request("DELETE", url, headers=headers, cookies=cookies)
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

# Same coding ground contract as log_function_checker: the submission replaces
# a module of the running app, so it stays behind authentication.
@authentication_decorator
def A6_disscussion_api_2(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)
    code = request.POST.get('code')
    # Server chosen destination, size cap and syntax check (see utility.py).
    try:
        write_lab_code('A6_utility', code)
    except LabCodeRejected as rejected:
        return JsonResponse({"message": "invalid code: {}".format(rejected)}, status=400)
    except OSError:
        return JsonResponse({"message": "code could not be saved"}, status=500)
    return JsonResponse({"message":"success"},status = 200)