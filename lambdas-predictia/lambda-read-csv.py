import boto3
import pandas as pd
import io

def lambda_handler(event, context):
    # Parámetros del evento
    bucket_name = 'predictiadata'
    file_key = 'data_csv/totals_results.csv'
    
    # Crear un cliente de S3
    s3_client = boto3.client('s3')
    
    # Obtener el archivo CSV de S3
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    
    if status == 200:
        print(f"Successfully retrieved file from S3: {file_key}")
        csv_content = response['Body'].read().decode('utf-8')
        
        # Leer el contenido CSV en un DataFrame de pandas
        df = pd.read_csv(io.StringIO(csv_content))
        
        # Convertir el DataFrame en un JSON
        json_data = df.to_json(orient='records')
        
        # Retornar la respuesta en formato JSON
        return {
            'statusCode': 200,
            'body': json_data
        }
    else:
        print(f"Failed to retrieve file from S3. Status - {status}")
        return {
            'statusCode': status,
            'body': 'Failed to retrieve file from S3'
        }
