from commons.log_helper import get_logger
from commons.abstract_lambda import AbstractLambda
import json
import boto3
import uuid
import re
from datetime import datetime,timezone
import os
_LOG = get_logger(__name__)

# Initialize AWS services
cognito_client = boto3.client("cognito-idp")

CUP_ID = os.environ['cup_id']
CLIENT_ID = os.environ['cup_client_id']

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
PASSWORD_REGEX = r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{12,}$"


class ApiHandler(AbstractLambda):
    def handle_request(self,event, context):
        
        request_path = event.get('resource','')
        http_method = event.get("httpMethod", "")
        user_service = UserService()
        if request_path == '/signup' and http_method == 'POST':
            body = json.loads(event['body'])
            email = body.get('email')
            password = body.get('password')
            first_name = body.get('firstName')
            last_name = body.get('lastName')
            created_at = str(int(datetime.utcnow().timestamp()))
            return user_service.signup(first_name,last_name, email, password,created_at)
            
        elif request_path == '/signin' and http_method == 'POST':
            body = json.loads(event['body'])
            email = body.get('email')
            password = body.get('password')
            return user_service.signin(email,password)
        else:
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({'message': 'Unknown request path'})
                }

class UserService:

    def signup(self,first_name,last_name,email,password,created_at):
        if not re.match(EMAIL_REGEX, email):
            return self.error_response('Invalid email format.')

        if not re.match(PASSWORD_REGEX, password):
            return self.error_response('Password must be alphanumeric with special characters and at least 12 characters long.')
        
        custom_attr = [
            {'Name': 'email', 'Value': email},
            {'Name': 'given_name', 'Value': first_name},
            {'Name': 'family_name', 'Value': last_name},
            {'Name': 'updated_at', 'Value': created_at}
        ]

        try:
            
            cognito_client.sign_up(
                ClientId = CLIENT_ID,
                Username=email,
                Password = password,
                UserAttributes=custom_attr
                )
            cognito_client.admin_confirm_sign_up(
                UserPoolId = CUP_ID, Username=email
            )
            
        except Exception as e:
            print(str(e))
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'message':f'Cannot create user {email}.'})
            }
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({'message': f'User {email} was created.'})
            }
            
    def signin(self,email, password):
        if not re.match(EMAIL_REGEX, email):
            return self.error_response('Invalid email format.')

        if not re.match(PASSWORD_REGEX, password):
            return self.error_response('Password must be alphanumeric with special characters and at least 12 characters long.')

        auth_params = {
            'USERNAME': email,
            'PASSWORD': password
        }
        try:
            auth_result = cognito_client.admin_initiate_auth(
                UserPoolId=CUP_ID,
                ClientId=CLIENT_ID,
                AuthFlow='ADMIN_USER_PASSWORD_AUTH', AuthParameters=auth_params)

            if auth_result:
                access_token = auth_result['AuthenticationResult']['IdToken']
            else:
                access_token = None

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    #"Authorization": f"Bearer {access_token}"
                },
                "body": json.dumps({"accessToken":access_token})
            }
        except Exception:
            return self.error_response('User does not exist or password is incorrect')

    def verify_token(self,event):
        try:
            auth_header = event.get('headers', {}).get('Authorization', '')
            access_token = auth_header.split(" ")[1]
        except Exception:
            if not access_token:
                return {
                    "statusCode": 401,
                    "body": json.dumps({"message": "Unauthorized"})
                }
    def error_response(self,message):
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({'message': message})
        }
HANDLER = ApiHandler()



def lambda_handler(event, context):
    return HANDLER.lambda_handler(event=event, context=context)
