import os
import boto3
import json

# Inicializar el cliente de S3
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    # Especificar el nombre del bucket y la clave del archivo
    bucket_name = os.getenv("BUCKET_NAME")  # Reemplaza con el nombre de tu bucket
    file_key = 'insights/insights.txt'  # Reemplaza con la clave del archivo en S3

    try:
        # Obtener el archivo de S3
        file_obj = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        
        # Leer el contenido del archivo
        file_content = file_obj['Body'].read().decode('utf-8')
        
        # Retornar el contenido del archivo en formato JSON
        return {
            'statusCode': 200,
            'body': json.dumps({'content': file_content})
        }
    except Exception as e:
        raise f"Error: {e}"
