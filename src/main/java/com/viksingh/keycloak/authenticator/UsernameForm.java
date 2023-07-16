package com.viksingh.keycloak.authenticator;

import com.viksingh.keycloak.authenticator.service.SmsServiceFactory;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Locale;

public class UsernameForm extends AbstractUsernameFormAuthenticator implements Authenticator {
    protected static ServicesLogger log;

    private static final String TPL_CODE = "login-sms.ftl";

    public UsernameForm() {
    }

    public void action(AuthenticationFlowContext context) {
        String enteredCode = context.getHttpRequest().getDecodedFormParameters ().getFirst(SMSAuthenticatorConstants.CODE);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote(SMSAuthenticatorConstants.CODE);
        String ttl = authSession.getAuthNote(SMSAuthenticatorConstants.CODE_TTL);

        if (code == null || ttl == null) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        boolean isValid = enteredCode.equals(code);
        if (isValid) {
            if (Long.parseLong(ttl) < System.currentTimeMillis()) {
                // expired
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                        context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
            } else {
                // valid
                context.success();
            }
        } else {
            // invalid
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setAttribute("realm", context.getRealm())
                                .setError("smsAuthCodeInvalid").createForm(TPL_CODE));
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return this.validateUser(context, formData);
    }

    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
        String loginHint = context.getAuthenticationSession().getClientNote("login_hint");
        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());
        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute("usernameHidden", true);
            form.setAttribute("registrationDisabled", true);
        } else {
            context.getAuthenticationSession().removeAuthNote("USER_SET_BEFORE_USERNAME_PASSWORD_AUTH");
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add("username", loginHint);
                } else {
                    formData.add("username", rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }
        createOtpChallenge(context,formData);
    }

    public void createOtpChallenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData){
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        KeycloakSession session = context.getSession();
        int length = Integer.parseInt(config.getConfig().get(SMSAuthenticatorConstants.CODE_LENGTH));
        int ttl = Integer.parseInt(config.getConfig().get(SMSAuthenticatorConstants.CODE_TTL));

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(SMSAuthenticatorConstants.CODE, code);
        authSession.setAuthNote(SMSAuthenticatorConstants.CODE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

        try {
            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
            Locale locale = session.getContext().resolveLocale(context.getUser() );
            String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");
            String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

            SmsServiceFactory.get(config.getConfig()).send(context.getUser().getUsername (), smsText);

            context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
        } catch (Exception e) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsAuthSmsNotSent", e.getMessage())
                            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        }
    }

    public boolean requiresUser() {
        return false;
    }


    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    public void close() {
    }

    static {
        log = ServicesLogger.LOGGER;
    }
}
