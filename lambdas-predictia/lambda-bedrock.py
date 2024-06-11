import json
import logging
import boto3
import pandas as pd
from io import StringIO

# Initialize logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize boto3 clients
s3_client = boto3.client('s3')
bedrock_runtime = boto3.client(service_name='bedrock-runtime')  # Ensure this is correctly set up

def lambda_handler(event, context):
    # Load data from S3
    data = load_csv_from_s3('predictiadata', 'forecast/forecast-data.csv')
    # print(data.head())
    print('The data is:\n')
    print(data)

    # Generate content using the model
    model_id = 'anthropic.claude-3-haiku-20240307-v1:0'
    # prompt = "Dame los insights y alertas más importantes de estos datos:" + str(data)
    # prompt = "Dame el pronóstico sumarizado para todos los identificadores unique_id y por mes de estos datos:" + str(data) + '.\n No agregues preámbulos o texto innecesario, sólo la tabla de resultados, donde los renglones serán los productos y las columnas los meses.'
    # prompt = "Dame el pronóstico sumarizado por identificador y por mes de la sección llamada forecast de estos datos:" + data + '. No agregues preámbulos o texto innecesario, sólo la tabla de resultados.'    
    prompt = "Dame el pronóstico sumarizado por identificador y por mes para el siguientes mes de la sección llamada forecast de estos datos:" + data + '. No agregues preámbulos o texto innecesario, sólo la tabla de resultados. La tabla debe tener dos columnas, de nombre Producto y la otra con el año-mes siguiente.'    
    prompt2 = "De acuerdo a este pronóstico, sección llamada forecast de estos datos:" + data + 'dime qué tengo que comprar el siguiente mes de forma sencilla como si le hablaras con confianza a la señora de la tiendita de la esquina, muy coloquial.'    

    try:
        text_content = invoke_model_and_get_response(model_id, prompt, 10000)
        text_content2 = invoke_model_and_get_response(model_id, prompt2, 10000)
    except Exception as e:
        logger.error(f"Failed to invoke model: {e}")
        raise

    # Upload the text content to S3
    try:
        upload_to_s3('predictiadata', 'insights/insights_simplified.txt', text_content)
        upload_to_s3('predictiadata', 'insights/insights.txt', text_content2)
    except Exception as e:
        logger.error(f"Failed to upload file to S3: {e}")
        raise

    return text_content

def load_csv_from_s3(bucket_name, file_name):
    response = s3_client.get_object(Bucket=bucket_name, Key=file_name)
    file_content = response['Body'].read().decode('utf-8')
    data = pd.read_csv(StringIO(file_content))
    data = data[data['type']=='forecast']
    data['y'] = round(data['y'],0)
    data = data.drop(columns='type')
    return data.to_csv(index=False)

def invoke_model_and_get_response(model_id, prompt, max_tokens):
    messages = [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
    print(messages)
    response = run_multi_modal_prompt(model_id, messages, max_tokens)
    text_content = response['content'][0]['text']
    return text_content

def upload_to_s3(bucket_name, file_name, content):
    s3_client.put_object(Bucket=bucket_name, Body=content, Key=file_name)
    logger.info(f'File successfully uploaded to s3://{bucket_name}/{file_name}')

def run_multi_modal_prompt(model_id, messages, max_tokens):
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "system": "Contesta como si hablases con una persona no técnica de retail",
        # "system": "Contesta como un analista de datos de retail",
        "messages": messages
    })
    # Correct the method call with appropriate parameter names
    response = bedrock_runtime.invoke_model(
        body=body,  # Correct case for 'body'
        modelId=model_id  # Correct case for 'modelId'
    )
    response_body = json.loads(response['body'].read())  # Correctly access the response body
    return response_body
