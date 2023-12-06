from typing import Dict

from fastapi import APIRouter, HTTPException
from fastapi.security.http import HTTPBearer
from auth.app.JWTBearer import JWTBearer

from auth.app.auth import does_pub_key_belong_to_valid_actor, \
    is_pub_key_corresponding_to_address

router = APIRouter(
    prefix="/auth",
    tags=["EdDSA challenge-response authentication"],
    responses={404: {"detail": "Not found"}},
)

get_bearer_token = HTTPBearer(auto_error=False)


@router.get("/", summary="request a challenge that is to be signed and posted.")
async def get_challenge(public_key: str, address: str) -> dict[str, str]:
    public_key_bytes = bytes.fromhex(public_key)
    if does_pub_key_belong_to_valid_actor(public_key_bytes) and is_pub_key_corresponding_to_address(public_key, address):
        challenge = JWTBearer.signJWT(public_key)
        return challenge
    raise HTTPException(status_code=403, detail="Invalid public key.")

@router.get("/verify", summary="Verify a signed challenge.")
async def get_verify(token: str) -> bool:
    decoded_token = JWTBearer.verify_token_payload(token)
    if decoded_token is not None:
        print(decoded_token)
        return decoded_token
    else:
        raise HTTPException(status_code=403, detail="Invalid token or expired token.")


# @router.post("/", summary="Send the signed challenge to get access and refresh tokens.")
# async def post_signed_challenge(public_key: str, signature: str) -> dict:
#     if verify_signed_challenge(public_key, signature):
#         response = JWTBearer.signJWT(public_key)
#         return response
#     else:
#         raise HTTPException(status_code=403, detail="Invalid token or expired token.")
