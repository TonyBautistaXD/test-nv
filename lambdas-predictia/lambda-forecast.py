import os
import json
import boto3
import pandas as pd
from io import StringIO

#Lambda layer: arn:aws:lambda:us-east-1:770693421928:layer:Klayers-p312-pandas:2


def lambda_handler(event, context):
    # Configura el nombre del bucket y el nombre del archivo
    bucket_name = os.getenv("BUCKET_NAME")
    file_name = 'forecast/forecast-data.csv'

    # Crea un cliente de S3
    s3_client = boto3.client('s3')

    # Lee el archivo desde S3
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=file_name)
        file_content = response['Body'].read().decode('utf-8')

        # Convierte el contenido del archivo a un DataFrame de Pandas
        data = pd.read_csv(StringIO(file_content))

        # Obtiene los IDs del evento JSON y conviértelos a enteros
        unique_ids = [int(id) for id in event.get('unique_ids', [])]

        # Filtra el DataFrame para los IDs proporcionados, asegurándote de que los IDs en el DataFrame sean enteros
        # Esta línea asume que los unique_id en el DataFrame ya son enteros. Si no es así, asegúrate de convertirlos.
        filtered_data = data[data['unique_id'].isin(unique_ids)]

        # Convierte el DataFrame filtrado a formato JSON
        result_json = filtered_data.to_json(orient='records')

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Datos obtenidos exitosamente',
                'data': json.loads(result_json)
            })
        }
    except Exception as e:
        raise f"Error: {e}"
