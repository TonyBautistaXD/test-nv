import os
import boto3
import json
from botocore.exceptions import ClientError

COGNITO_REGION = os.getenv("region_aws")
SES_REGION = COGNITO_REGION  # Assuming SES is in the same region, adjust if necessary
cognito_pool_id = os.getenv("pool_id")
cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
ses_client = boto3.client('ses', region_name=SES_REGION)
s3_client = boto3.client('s3', region_name=COGNITO_REGION)
lambda_client = boto3.client('lambda')

def get_last_created_user(pool_id):
    # target_lambda_function_name = 'lambda-bedrock'
    # lambda_client.invoke(
    #     FunctionName=target_lambda_function_name
    # )
    users_resp = cognito_client.list_users(UserPoolId=pool_id, AttributesToGet=['email'])
    usernames = []
    for user in users_resp['Users']:
        user_record = {'username': user['Username'], 'email': None}
        for attr in user['Attributes']:
            if attr['Name'] == 'email':
                user_record['email'] = attr['Value']
                usernames.append(user_record)
                break
    return usernames

def send_email_with_ses(to_email, subject, body):
    try:
        response = ses_client.send_email(
            Source='valid@email.com',  # Replace with your verified sender email address
            Destination={'ToAddresses': [to_email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body}}
            }
        )
        return response
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None

def create_presigned_url(bucket_name, object_name, expiration=3600):
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except ClientError as e:
        print(e)
        return None
    return response

def lambda_handler(event, context):
    user_pool_id = cognito_pool_id
    last_user = get_last_created_user(user_pool_id)
    if last_user:
        email = last_user[0]["email"]
        bucket_name = 'predictiadata'  # Replace with your bucket name
        object_name = 'forecast/forecast-data.csv'  # Assuming the file is in the root of the bucket
        object2_name = 'insights/insights_simplified.pdf'  # Assuming the file is in the root of the bucket
        presigned_url = create_presigned_url(bucket_name, object_name)
        presigned_url2 = create_presigned_url(bucket_name, object2_name)
        subject = "Analysis Process Finished"
        body = f"Analysis process has been completed. You can download the file from the following link: {presigned_url}\nAnd the pdf witht he simplified predictions from: {presigned_url2}"
        send_email_response = send_email_with_ses(email, subject, body)
        response = {
            'statusCode': 200,
            'body': json.dumps({'message': 'Email sent successfully', 'ses_response': str(send_email_response)})
        }
    else:
        response = {
            'statusCode': 400,
            'body': json.dumps({'message': 'User Not Found. Email not sent'})
        }
    return response
