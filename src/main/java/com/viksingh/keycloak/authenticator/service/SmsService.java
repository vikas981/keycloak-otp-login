package com.viksingh.keycloak.authenticator.service;




public interface SmsService {

	void send(String phoneNumber, String message);

}
