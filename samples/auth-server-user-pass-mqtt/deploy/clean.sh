#!/bin/bash

POD_NAME="${POD_NAME:-auth-server-user-pass-mqtt}"

CA_CERT_NAME="${CA_CERT_NAME:-custom-auth-ca}"
CLIENT_CERT_NAME="${CLIENT_CERT_NAME:-auth-server-user-pass-mqtt-client-cert}"
SERVER_CERT_NAME="${SERVER_CERT_NAME:-auth-server-user-pass-mqtt-server-cert}"

kubectl delete cm --ignore-not-found=true "$CA_CERT_NAME"
# TODO: check if secret and cert name can be different?
kubectl delete secret --ignore-not-found=true "$SERVER_CERT_NAME" "$CLIENT_CERT_NAME"
kubectl delete service --ignore-not-found=true "$POD_NAME"
kubectl delete pod --ignore-not-found=true --wait=false "$POD_NAME"
