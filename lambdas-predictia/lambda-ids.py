import os
import json
import boto3
import pandas as pd
from io import StringIO

#Lambda layer: arn:aws:lambda:us-east-1:770693421928:layer:Klayers-p312-pandas:2

def lambda_handler(event, context):
    # Configura el nombre de tu bucket y el nombre del archivo
    bucket_name = os.getenv("BUCKET_NAME")
    file_name = 'forecast/forecast-data.csv'

    # Crea un cliente de S3
    s3_client = boto3.client('s3')

    try:
        # Lee el archivo desde S3
        response = s3_client.get_object(Bucket=bucket_name, Key=file_name)
        file_content = response['Body'].read().decode('utf-8')

        # Convierte el contenido del archivo a un DataFrame de Pandas
        data = pd.read_csv(StringIO(file_content))

        # Recupera todos los unique_ids del DataFrame y asegúrate de que sean enteros
        unique_ids = data['unique_id'].unique().tolist()
        unique_ids = [int(id) for id in unique_ids]

        # Devuelve los unique_ids como una lista de enteros en la respuesta JSON
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Unique IDs obtenidos exitosamente',
                'unique_ids': unique_ids
            })
        }
    except Exception as e:
        raise f"Error: {e}"
