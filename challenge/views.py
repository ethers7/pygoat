from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
import os
import re
from .utility import get_free_port
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

        if not re.match(r'^\d+$', str(port)):
            return JsonResponse({'message': 'failed', 'status': '500', 'endpoint': 'None'})
        if not re.match(r'^[a-zA-Z0-9._:/-]+$', str(chal.docker_image)):
            return JsonResponse({'message': 'failed', 'status': '500', 'endpoint': 'None'})
        if not re.match(r'^\d+$', str(chal.docker_port)):
            return JsonResponse({'message': 'failed', 'status': '500', 'endpoint': 'None'})
        docker_cmd = f"/usr/bin/docker run -d -p {port}:{chal.docker_port} {chal.docker_image}"
        with os.popen(docker_cmd) as proc:
            container_id = proc.read().strip()
        
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

        user_chal.is_live = False
        user_chal.save()
        # Validate container_id is a valid docker container ID (hex string)
        container_id = user_chal.container_id
        if not container_id or not re.match(r'^[a-f0-9]+$', container_id):
            return JsonResponse({'message': 'failed', 'status': '400'})
        os.popen(f"/usr/bin/docker stop {container_id}").read()
        return JsonResponse({'message': 'success', 'status': '200'})
    
    def put(self, request, challange):
        # TODO : implement flag checking
        return "not implemented"
    