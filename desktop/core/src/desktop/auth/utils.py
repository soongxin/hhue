#! /usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'xj'

import base64
import binascii
import hashlib

from Crypto.Cipher import AES, DES
from Crypto.Hash import MD5, SHA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA

from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode
from jose import jws


class RSACrypter(object):
  def __init__(self, public_key=None, private_key=None):
    self.public_key = public_key
    self.private_key = private_key

  def encrypt(self, message):
    rsa_key = RSA.importKey(self.public_key)
    cipher = Cipher_pkcs1_v1_5.new(rsa_key)
    return base64.b64encode(cipher.encrypt(message))

  def decrypt(self, text):
    random_generator = Random.new().read
    rsa_key = RSA.importKey(self.private_key)
    cipher = Cipher_pkcs1_v1_5.new(rsa_key)
    return cipher.decrypt(base64.b64decode(text), random_generator)


def pkcs7_pad(somebytes, blocksize):
  """
  Return a copy of somebytes with PKCS #7 padding added, bringing the length
  up to an even multiple of blocksize.
  """
  somebytes = somebytes.encode('utf-8')
  pad_bytes = blocksize - (len(somebytes) % blocksize)
  temp = [pad_bytes] * pad_bytes
  result = bytes(somebytes) + bytes(temp)
  return result


def pkcs7_unpad(somebytes):
  return somebytes[:-somebytes[-1]]


def get_sha1prng_key(key):
  signature = hashlib.sha1(key.encode()).digest()
  signature = hashlib.sha1(signature).digest()
  return bytes.fromhex(''.join(['%02x' % i for i in signature]).upper()[:32])


class AESCrypter(object):

  def __init__(self, key, iv, mode, segment_size):
    self.key = key
    self.iv = iv
    self.mode = mode
    self.segment_size = segment_size

  @property
  def aes(self):
    return AES.new(self.key, self.mode, self.iv, segment_size=self.segment_size)

  def encrypt(self, plaintext):
    plaintext = pkcs7_pad(plaintext, AES.block_size)
    encrypted_text = self.aes.encrypt(plaintext)
    return binascii.b2a_base64(encrypted_text).rstrip().decode('utf-8')

  def decrypt(self, encrypted_text):
    encrypted_text_bytes = binascii.a2b_base64(encrypted_text)
    decrypted_text = self.aes.decrypt(encrypted_text_bytes)
    decrypted_text = pkcs7_unpad(decrypted_text)
    return decrypted_text


class PBECrypter(object):

  def __init__(self, pwd, salt, iterations):
    hasher = MD5.new()
    hasher.update(pwd)
    hasher.update(salt)
    self.result = hasher.digest()
    for i in range(1, iterations):
      hasher = MD5.new()
      hasher.update(self.result)
      self.result = hasher.digest()

  @property
  def des(self):
    return DES.new(self.result[:8], DES.MODE_CBC, self.result[8:16])

  def encrypt(self, plaintext):
    plaintext = pkcs7_pad(plaintext, 8)
    encrypted_text = self.des.encrypt(plaintext)
    return binascii.b2a_base64(encrypted_text).rstrip()

  def decrypt(self, encrypted_text):
    encrypted_text_bytes = binascii.a2b_base64(encrypted_text)
    decrypted_text = self.des.decrypt(encrypted_text_bytes)
    decrypted_text = pkcs7_unpad(decrypted_text)
    return decrypted_text


class SHACrypter(object):
  def __init__(self, data):
    hasher = SHA.new()
    hasher.update(data)
    self.result = hasher.hexdigest()

  @property
  def hashed_data(self):
    return self.result


class JWTEncrypt(object):

  def __init__(self, sign_key, enc_key):
    self.sign_key = sign_key
    self.enc_key = enc_key

  def decode(self, token):
    e_payload = self._verify_signature(token)
    e_payload = e_payload.decode('utf-8')
    payload = self._decode_encrypted_payload(e_payload)
    return json_decode(payload)

  def _verify_signature(self, token):
    return jws.verify(token, self.sign_key, algorithms=['HS512'])

  def _decode_encrypted_payload(self, encrypted_payload):
    expkey = {"k": "{0}".format(self.enc_key), "kty": "oct"}
    key = jwk.JWK(**expkey)
    payloadlist = encrypted_payload.rsplit(".")
    d_enc = {
      "ciphertext": "{}".format(payloadlist[3]),
      "encrypted_key": "{}".format(payloadlist[1]),
      "iv": "{}".format(payloadlist[2]),
      "protected": "{}".format(payloadlist[0]),
      "tag": "{}".format(payloadlist[4])
    }

    jwetoken = jwe.JWE()
    jwetoken.deserialize(json_encode(d_enc))
    jwetoken.decrypt(key)
    payload = jwetoken.payload
    return payload


if __name__ == '__main__':
    # KEY = '33b21adee1b8620a7ba81aea1a80c724'
    # import random
    # IV = random.randint()
    # data = {
    #     'key': 100,
    #     'value': 200
    # }
    # import json
    # MODE = AES.MODE_CBC
    # SEGMENT_SIZE = 128
    # aes_crypter = AESCrypter(KEY, IV, MODE, SEGMENT_SIZE)
    # a = aes_crypter.encrypt(json.dumps(data))
    # print a
    # print aes_crypter.decrypt(a)
    # import rsa
    with open('/Users/songxin/Documents/RRD/rrd-loan-dashboard/common/apis/rsa_public_key.pem') as f:
        p = f.read()
    # pk = rsa.PublicKey.load_pkcs1(p)
    crypter = RSACrypter(public_key=p)
    # a = PBECrypter('q1w2e3r4t5y6', '\x80\x40\xe0\x10\xf8\x04\xfe\x01', 50)
    # b = a.encrypt('MyP455w0rd')
    # print b
    # print a.decrypt(b)
    # from common.base_utils import set_configs
    # set_configs()
    # from tornado.options import options
    # rsa = RSACrypter(public_key=options.credit_report_spiders_rsa_public_key,
    #                  private_key=options.credit_report_spiders_rsa_private_key)
    # a = rsa.encrypt('haohuan')
    # print a
    # print rsa.decrypt(a)