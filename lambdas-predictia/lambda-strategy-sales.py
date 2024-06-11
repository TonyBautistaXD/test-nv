import logging
import boto3
import json

# Initialize logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize boto3 clients
bedrock_runtime = boto3.client(service_name='bedrock-runtime')  # Ensure this is correctly set up

def lambda_handler(event, context):
    try:
        # Lambda Event
        data = event
        logger.info(f"Received raw text data: {data}")

        # Generate content using the model
        model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        prompt = f"El siguiente JSON contiene información sobre las ventas del punto de venta a nivel hora. Su tarea es darme una estrategia de venta, los KPIs de esa información, recomendación de gráficas para pintar la data y asi mismo dame recomendaciones sobre puntos clave en donde enfocarme. JSON de entrada: {str(data)}"
        logger.info(f"Prompt sent to model: {prompt}")

        text_content = invoke_model_and_get_response(model_id, prompt, 10000)
        logger.info(f"Received text content from model: {text_content}")

        # Encapsulate the text_content in a success response object
        response_object = {
            "success": True,
            "statusCode": 200,
            "message": "Request successfully.",
            "data": text_content
        }
    except Exception as e:
        logger.error(f"Error in lambda_handler: {e}")
        # Encapsulate the error message in a failure response object
        response_object = {
            "success": False,
            "statusCode": 500,
            "error_message": str(e)
        }

    logger.info(f"Returning response object: {response_object}")
    return response_object

def invoke_model_and_get_response(model_id, prompt, max_tokens):
    try:
        messages = [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
        logger.info(f"Invoking model with prompt: {prompt}")

        response = run_multi_modal_prompt(model_id, messages, max_tokens)
        text_content = response['content'][0]['text']
        logger.info(f"Received response from model: {response}")
        return text_content
    except Exception as e:
        logger.error(f"Error in invoke_model_and_get_response: {e}")
        raise

def run_multi_modal_prompt(model_id, messages, max_tokens):
    try:
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": "Responde solo con lo que te pido.",
            "messages": messages
        })
        logger.info(f"Sending request to model with body: {body}")

        # Correct the method call with appropriate parameter names
        response = bedrock_runtime.invoke_model(
            body=body,  # Correct case for 'body'
            modelId=model_id  # Correct case for 'modelId'
        )
        response_body = json.loads(response['body'].read())  # Correctly access the response body
        logger.info(f"Received response from model runtime: {response_body}")
        return response_body
    except Exception as e:
        logger.error(f"Error in run_multi_modal_prompt: {e}")
        raise