from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Team
from .serializers import TeamSerializer
# Create your views here.

@api_view(["GET"])
def team_list_view(request):
    teams=Team.objects.all()
    serializer=TeamSerializer(teams,many=True)
    return Response(serializer.data)
