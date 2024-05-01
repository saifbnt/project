from django.contrib.auth import get_user_model, login, logout
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserRegisterSerializer, UserLoginSerializer, UserSerializer
from rest_framework import permissions, status
from .validations import custom_validation, validate_email, validate_password
from django.http import JsonResponse
import subprocess


class UserRegister(APIView):
	permission_classes = (permissions.AllowAny,)
	def post(self, request):
		clean_data = custom_validation(request.data)
		serializer = UserRegisterSerializer(data=clean_data)
		if serializer.is_valid(raise_exception=True):
			user = serializer.create(clean_data)
			if user:
				return Response(serializer.data, status=status.HTTP_201_CREATED)
		return Response(status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
	permission_classes = (permissions.AllowAny,)
	authentication_classes = (SessionAuthentication,)
	##
	def post(self, request):
		data = request.data
		assert validate_email(data)
		assert validate_password(data)
		serializer = UserLoginSerializer(data=data)
		if serializer.is_valid(raise_exception=True):
			user = serializer.check_user(data)
			login(request, user)
			return Response(serializer.data, status=status.HTTP_200_OK)


class UserLogout(APIView):
	permission_classes = (permissions.AllowAny,)
	authentication_classes = ()
	def post(self, request):
		logout(request)
		return Response(status=status.HTTP_200_OK)


class UserView(APIView):
	permission_classes = (permissions.IsAuthenticated,)
	authentication_classes = (SessionAuthentication,)
	##
	def get(self, request):
		serializer = UserSerializer(request.user)
		return Response({'user': serializer.data}, status=status.HTTP_200_OK)
	

	#############
""" 

class SQLInjectionTest(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (SessionAuthentication,)

    def get(self, request):
        return Response({"message": "This endpoint accepts only POST requests."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def post(self, request):
        if 'target_url' not in request.data:
            return Response({'error': 'Target URL is required'}, status=status.HTTP_400_BAD_REQUEST)

        target_url = request.data['target_url']

        # Exécute SQLMap avec l'URL cible à l'intérieur du conteneur Docker
        command = f'docker run --rm sqlmapproject/sqlmap -u {target_url} --safe-url'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        # Renvoyer les résultats
        if error:
            return Response({'error': error.decode('utf-8')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'output': output.decode('utf-8')}, status=status.HTTP_200_OK)

"""

class SQLInjectionTest(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (SessionAuthentication,)

    def post(self, request):
        if 'target_url' not in request.data:
            return Response({'error': 'Target URL is required'}, status=status.HTTP_400_BAD_REQUEST)

        target_url = request.data['target_url']

        # Exécute SQLMap avec l'URL cible directement
        command = f'sqlmap -u {target_url} --safe-url'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

		######
class NmapScan(APIView):
    def post(self, request):
        if 'target' not in request.data:
            return Response({'error': 'Target IP address or hostname is required'}, status=status.HTTP_400_BAD_REQUEST)

        target = request.data['target']

        # Exécute Nmap avec l'adresse cible
        command = f'nmap {target}'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        # Renvoyer les résultats
        if error:
            return Response({'error': error.decode('utf-8')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'output': output.decode('utf-8')}, status=status.HTTP_200_OK)
		
class NoSQLMapScan(APIView):
    def post(self, request):
        if 'target_url' not in request.data:
            return Response({'error': 'Target URL is required'}, status=status.HTTP_400_BAD_REQUEST)

        target_url = request.data['target_url']

        # Exécute NoSQLMap avec l'URL cible
        command = f'nosqlmap -u {target_url}'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        # Renvoyer les résultats
        if error:
            return Response({'error': error.decode('utf-8')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'output': output.decode('utf-8')}, status=status.HTTP_200_OK)



class XSSerScan(APIView):
    def post(self, request):
        if 'target_url' not in request.data:
            return Response({'error': 'Target URL is required'}, status=status.HTTP_400_BAD_REQUEST)

        target_url = request.data['target_url']

        # Exécute XSSer avec l'URL cible
        command = f'xsser -u {target_url}'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        # Renvoyer les résultats
        if error:
            return Response({'error': error.decode('utf-8')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'output': output.decode('utf-8')}, status=status.HTTP_200_OK)

		