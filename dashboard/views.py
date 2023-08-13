import boto3
from django.shortcuts import render, redirect, HttpResponse
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
# Initialize the QuickSight client
quicksight_client = boto3.client('quicksight', region_name=settings.AWS_REGION)
@login_required(login_url='login')
def login_view(request):
    if request.method == 'POST':
        # Process the login form
        username = request.POST.get('username')
        pass1=request.POST.get('pass')
        user=authenticate(request,username=username,password=pass1)
        if user is not None:
            login(request,user)
            user_arn = f'arn:aws:quicksight:us-east-1:233425133219:user/default/{username}'

            # Save the user ARN to the session
            request.session['user_arn'] = user_arn
            return redirect('dashboard')
        else:
            return HttpResponse("Username or password is incorrect")



        # user_arn = f'arn:aws:quicksight:us-east-1:233425133219:user/default/{username}'

        # Save the user ARN to the session
        # request.session['user_arn'] = user_arn

        #return redirect('dashboard')
    else:
        return render(request, 'login.html')
    
def signup_view(request):
    if request.method=='POST':
        uname=request.POST.get('username')
        email=request.POST.get('email')
        pass1=request.POST.get('password1')
        pass2=request.POST.get('password2')
        if pass1!=pass2:
            return HttpResponse("Your password is not the same")
        else:
            my_user=User.objects.create_user(uname,email,pass1)
            my_user.save()
            iam_client = boto3.client('iam')
        
       
        # Create the IAM user
        iam_client.create_user(UserName=uname)
       
        
        # Set the password for the user
        iam_client.create_login_profile(UserName=uname, Password=pass1, PasswordResetRequired=False)
        dashboard_name=uname

       
        # Attach the required policy to the user
        policy_name = 'DashboardAccessPolicy'
        d_arn=f'arn:aws:quicksight:*:*:dashboard/{dashboard_name}'
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 'quicksight:GetDashboardEmbedUrl',
                'Resource': d_arn
            }]
        }
        iam_client.put_user_policy(UserName=uname, PolicyName=policy_name, PolicyDocument=str(policy_document))


        # Save the user ARN to the session
        #request.session['user_arn'] = user_arn

            
        return redirect('temp')

    return render(request,'signup.html')

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


def logout_view(request):
    logout(request)
    return redirect('login')

def temp_view(request):
    if request.method=='POST':
        return redirect('login')

    return render(request,'temp.html')