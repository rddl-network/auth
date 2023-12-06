from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import jwt
import time
from typing import Dict, Optional
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Configuration (Replace these with your actual configurations)
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 360000
JWT_PRIVATE_KEY_PATH = "/Users/stefanwe/code/rddl/auth/private_key.pem"  # Replace with the path to your RSA private key
JWT_PUBLIC_KEY_PATH = "/Users/stefanwe/code/rddl/auth/public_key.pem"  # Replace with the path to your RSA public key
JWT_ALGORITHM = "RS256"
JWT_DOMAIN = "rddl.io"  # Replace with your actual domain


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not JWTBearer.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    @staticmethod
    def verify_jwt(jwtoken: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = JWTBearer.decodeJWT(jwtoken)
        except:
            payload = None
        if payload:
            isTokenValid = True
        return isTokenValid

    @staticmethod
    def token_response(token: str):
        return {"access_token": token}

    @staticmethod
    def _load_rsa_key(path: str, is_private: bool = False):
        with open(path, "rb") as key_file:
            if is_private:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            else:
                return serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )

    @staticmethod
    def verify_client_id(jwt_token: str) -> bool:
        decoded_token = JWTBearer.decodeJWT(jwt_token)
        if decoded_token:
            registered_public_key = JWTBearer._load_rsa_key(JWT_PUBLIC_KEY_PATH)
            public_key = decoded_token["actor"]
        if public_key == registered_public_key:
            return True
        return False

    @staticmethod
    def signJWT(public_key: str) -> Dict[str, str]:
        payload = {"actor": f"{public_key}@{JWT_DOMAIN}", "exp": time.time() + JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
                   "scope": "rabbitmq.write"}
        private_key = JWTBearer._load_rsa_key(JWT_PRIVATE_KEY_PATH, is_private=True)

        token = jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)

        # Calculate the expiring time and date of the JWT token.
        exp = payload["exp"]
        exp_datetime = datetime.fromtimestamp(exp)

        return {"token": token, "exp_datetime": exp_datetime}

    @staticmethod
    def verify_token_payload(token: str) -> Optional[Dict]:
        decoded_token = JWTBearer.decodeJWT(token)
        if decoded_token:
            if "actor" in decoded_token and decoded_token["actor"].endswith(f"@{JWT_DOMAIN}"):
                # Calculate the expiring time and date of the JWT token.
                exp = decoded_token["exp"]
                exp_datetime = datetime.fromtimestamp(exp)

                return {"decoded_token": decoded_token, "exp_datetime": exp_datetime}
            return None
        return None

    @staticmethod
    def decodeJWT(token: str) -> dict:
        try:
            if not token or token.count('.') != 2:
                print("Invalid or ill-formed token")
                return {}
        except Exception as e:
            print(f"An error occurred while decoding the token: {e}")
            raise HTTPBearer(description="Failed to decode JWT")

        public_key = JWTBearer._load_rsa_key(JWT_PUBLIC_KEY_PATH)

        try:
            decoded_token = jwt.decode(token, public_key, algorithms=[JWT_ALGORITHM])
            return decoded_token if decoded_token["exp"] >= time.time() else None
        except Exception as e:
            print(f"An error occurred while decoding the token: {e}")
            return {}
