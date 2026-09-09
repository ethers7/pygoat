from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
import subprocess
from .utility import (get_free_port, is_safe_container_id,
                      is_safe_docker_image, normalize_port)
from .models import Challenge, UserChallenge
# Create your views here.


class DoItFast(View):
    def get(self, request, challenge):
        if not request.user.is_authenticated:
            return redirect('login')
        
        try:
            chal = Challenge.objects.get(name=challenge)
        except Exception as e:
            return render(request, 'chal-not-found.html')

        try:
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
            return render(request, 'challenge.html', {'chal': chal, 'user_chal': user_chal})
        except:
            return render(request, 'challenge.html', {'chal': chal, 'user_chal': None})
    
    def post(self, request, challenge):
        user_chall_exists = False
        if not request.user.is_authenticated:
            return redirect('login')
        
        try: # checking the existance of challenge
            chal = Challenge.objects.get(name=challenge)
        except Exception as e:
            return render(request, 'chal-not-found.html')

        try: # checking if he attempted it before or not, if yes then check if the container is live or not
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
            if user_chal.is_live:
                return JsonResponse({'message':'already running', 'status': '200', 'endpoint': f'http://localhost:{user_chal.port}'})
            user_chall_exists = True
        except:
            pass

        port = get_free_port(8000, 8100)
        if port == None:
            return JsonResponse({'message': 'failed', 'status': '500', 'endpoint': 'None'})
        
        # The image reference and the container port come from stored challenge
        # records, so they are untrusted input for the command line. Allowlist
        # them at the trust boundary and fail closed.
        host_port = normalize_port(port)
        container_port = normalize_port(chal.docker_port)
        if (host_port is None or container_port is None
                or not is_safe_docker_image(chal.docker_image)):
            return JsonResponse({'message': 'failed', 'status': '500', 'endpoint': 'None'})

        # argv list + shell=False: the port mapping and the image reference each
        # stay a single argument, so shell metacharacters are never interpreted.
        command = ["docker", "run", "-d",
                   "-p", f"{host_port}:{container_port}",
                   chal.docker_image]
        process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE)
        output, error = process.communicate()
        container_id = output.decode('utf-8').strip()
        
        if user_chall_exists:
            # TODO : reuse the container instead of creaing the new one
            user_chal.container_id = container_id
            user_chal.port = port
            user_chal.is_live = True
            user_chal.save()
        else:
            user_chal = UserChallenge(user=request.user, challenge=chal, container_id=container_id, port=port)
            user_chal.save()
        # save the output in database for stoping the container 
        return JsonResponse({'message': 'success', 'status': '200', 'endpoint': f'http://localhost:{port}'})



    def delete(self, request, challenge):
        if not request.user.is_authenticated:
            return redirect('login')
    
        try:
            chal = Challenge.objects.get(name=challenge)
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
        except Exception as e:
            return JsonResponse({'message': 'failed', 'status': '500'})

        # Allowlist the untrusted portion at the trust boundary: only a plain
        # docker container id may reach the stop command. Fail closed otherwise.
        if not is_safe_container_id(user_chal.container_id):
            return JsonResponse({'message': 'failed', 'status': '500'})

        user_chal.is_live = False
        user_chal.save()
        # argv list + shell=False: the container id stays a single argument, so
        # shell metacharacters are never interpreted.
        command = ["docker", "stop", user_chal.container_id]
        process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE)
        output, error = process.communicate()
        return JsonResponse({'message': 'success', 'status': '200'})
    
    def put(self, request, challange):
        # TODO : implement flag checking
        return "not implemented"
    