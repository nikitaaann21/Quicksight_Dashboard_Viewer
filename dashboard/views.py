import boto3
from django.shortcuts import render, redirect
from django.conf import settings

# Initialize the QuickSight client
quicksight_client = boto3.client('quicksight', region_name=settings.AWS_REGION)
def login_view(request):
    if request.method == 'POST':
        # Process the login form
        user_arn = request.POST.get('user_arn')

        # Save the user ARN to the session
        request.session['user_arn'] = user_arn

        return redirect('dashboard')
    else:
        return render(request, 'login.html')

def dashboard_view(request):
    # Retrieve the user ARN from the session
    user_arn = request.session.get('user_arn')

    # Generate embed URL for the registered user
    embed_url = generateEmbedUrlForRegisteredUser(user_arn)

    return render(request, 'dashboard.html', {'embed_url': embed_url})

def generateEmbedUrlForRegisteredUser(user_arn):
    # Generate the embed URL using the QuickSight API
    response = quicksight_client.get_dashboard_embed_url(
        AwsAccountId=settings.AWS_ACCOUNT_ID,
        DashboardId=settings.QUICKSIGHT_DASHBOARD_ID,
        IdentityType='QUICKSIGHT',
        SessionLifetimeInMinutes=settings.QUICKSIGHT_SESSION_LIFETIME,
        UserArn=user_arn
    )
    embed_url = response['EmbedUrl']

    return embed_url
