package com.viksingh.keycloak.authenticator;

import com.google.auto.service.AutoService;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

@AutoService (AuthenticatorFactory.class)
@Slf4j
public class KeycloakSmsAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "mobile-authenticator";
    public static final KeycloakSmsAuthenticator SINGLETON = new KeycloakSmsAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit (KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close () {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Mobile Based User Form";
    }

    @Override
    public String getReferenceCategory () {
        return null;
    }

    @Override
    public String getHelpText() {
        return "Validates a mobile and password from login form.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices () {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                new ProviderConfigProperty(SMSAuthenticatorConstants.CODE_LENGTH, "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
                new ProviderConfigProperty(SMSAuthenticatorConstants.CODE_TTL, "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
                new ProviderConfigProperty(SMSAuthenticatorConstants.SENDER_ID, "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Vikash Singh"),
                new ProviderConfigProperty(SMSAuthenticatorConstants.SIMULATION_MODE, "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true)
        );
    }
}
