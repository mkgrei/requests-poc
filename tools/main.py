import time
import socket
import subprocess
import string
import random
import binascii
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512, SHA1
from Crypto.Signature import pss

import requests

import click

from kubernetes import client, config

run = subprocess.getoutput


def generate_sshkey(keyname):
    cmd = f'ssh-keygen -f {keyname} -N "" <<<y >/dev/null 2>&1'
    run(cmd)

    with open(f"{keyname}", 'r') as f:
        data = f.readlines()
    rkey = RSA.import_key(''.join(data))

    with open(f"{keyname}.pub", 'r') as f:
        data = f.readlines()
    pkey = RSA.import_key(''.join(data))
    return rkey, pkey


def create_access_request(url, path, pkey):
    cr = {
            'apiVersion': 'cr.requests.test/v1beta1',
            'kind': 'AccessRequest',
            'metadata': {},
            'spec': {},
            }

    cr['metadata']['name'] = socket.gethostname() + "-" + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(5))
    cr['spec']['pubKey'] = pkey.exportKey(format="OpenSSH").decode()

    try:
        req = requests.post(url+path, json=cr, verify=False)
    except:
        pass

    while True:
        req = requests.get(url+path+f"/{cr['metadata']['name']}", verify=False)
        ready = req.json().get('status', {}).get('ready', False)
        if ready:
            data = req.json()
            ca = data['status']['ca']
            token = data['status']['token']
            key = data['status']['key']
            print('access request accepted')
            break
        print('condition not met, waiting...')
        time.sleep(5)
    return ca, token, key


def decrypt_oaep(private_key, aes_ekey):
    d = PKCS1_OAEP.new(private_key, hashAlgo=SHA512, mgfunc=lambda x,y: pss.MGF1(x,y,SHA512))
    data = base64.b64decode(aes_ekey)
    m = d.decrypt(data)
    return m


def decrypt_aes(aes_key, edata):
    data = base64.b64decode(edata)
    nonce, emsg, tag = data[:12], data[12:-16], data[-16:]
    
    d = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    m = d.decrypt_and_verify(emsg, tag)
    return m


def generate_kubeconfig(url, ca, token):
    template = '''apiVersion: v1
kind: Config
contexts:
- context:
    cluster: cluster
    user: pod-viewer
  name: pod-viewer
current-context: pod-viewer
clusters:
- cluster:
    certificate-authority-data: {ca}
    server: {server}
  name: cluster
users:
- name: pod-viewer
  user:
    token: {token}
'''

    kubeconfig = template.format(
            token=token.decode(),
            ca=base64.b64encode(ca).decode(),
            server=url
            )
    fkubeconfig = "gen.kubeconfig"
    with open(fkubeconfig, 'w') as f:
        f.write(kubeconfig)
    return fkubeconfig


def watch_pods(fkubeconfig):
    config.load_kube_config(fkubeconfig)
    v1 = client.CoreV1Api()
    while True:
        ret = v1.list_namespaced_pod("default")
        print('----')
        for po in ret.items:
            print(f"{po.metadata.namespace} {po.metadata.name} {po.status.pod_ip}")
        time.sleep(5)


@click.command()
@click.option("--url", type=str, help="kubernetes cluster api server url", default="https://localhost:6443")
@click.option("--keyname", type=str, help="ssh key name", default="test")
def main(url, keyname):
    path = "/apis/cr.requests.test/v1beta1/accessrequests"

    rkey, pkey = generate_sshkey(keyname)
    eca, etoken, ekey = create_access_request(url, path, pkey)

    aes_key = decrypt_oaep(rkey, ekey)

    token = decrypt_aes(aes_key, etoken)
    ca = decrypt_aes(aes_key, eca)

    fkubeconfig = generate_kubeconfig(url, ca, token)
    watch_pods(fkubeconfig)


if __name__ == "__main__":
    main()
