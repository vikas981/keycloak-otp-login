package com.viksingh.keycloak.authenticator.service;

import java.util.Map;

public class Msg91Service implements SmsService{

	private final String senderId;

	public Msg91Service (Map<String, String> config) {
		this.senderId = config.get ("senderId");
	}

	@Override
	public void send (String phoneNumber, String message) {

	}
}
