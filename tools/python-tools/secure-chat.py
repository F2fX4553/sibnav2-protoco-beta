import sys
import os
import asyncio
import base64

# Ensure we can find the bindings
sys.path.append(os.path.join(os.path.dirname(__file__), '../../bindings/python'))

from secure_protocol import SecureContext, generate_keypair, ProtocolError

async def chat_client():
    print("Secure Chat Client v1.0")
    print("-----------------------")
    
    try:
        ctx = SecureContext()
        print("Secure Context initialized.")
        
        my_pub, my_priv = generate_keypair()
        print(f"My Public Key: {base64.b64encode(my_pub).decode()}")
        
        # In a real app, we would exchange keys and establish sessions here
        # This demonstrates the Python bindings are working
        
    except Exception as e:
        print(f"Error: {e}")
        return

if __name__ == "__main__":
    asyncio.run(chat_client())
