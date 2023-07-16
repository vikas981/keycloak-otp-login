package com.viksingh.keycloak.authenticator.service;

import com.viksingh.keycloak.authenticator.SMSAuthenticatorConstants;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
public class SmsServiceFactory {

	public static SmsService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault(SMSAuthenticatorConstants.SIMULATION_MODE, "false"))) {
			return (phoneNumber, message) ->
				log.warn(String.format("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message));
		} else {
			return (phoneNumber, message) ->
				log.warn(String.format("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message));
			//return new AwsSmsService(config);
		}
	}

}
