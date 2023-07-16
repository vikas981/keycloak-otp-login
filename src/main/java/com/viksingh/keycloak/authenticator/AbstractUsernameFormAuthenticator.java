package com.viksingh.keycloak.authenticator;

import lombok.extern.slf4j.Slf4j;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AbstractFormAuthenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

@Slf4j
public abstract class AbstractUsernameFormAuthenticator extends AbstractFormAuthenticator {
    private static final Logger logger = Logger.getLogger(AbstractUsernameFormAuthenticator.class);
    public static final String REGISTRATION_FORM_ACTION = "registration_form";
    public static final String ATTEMPTED_USERNAME = "ATTEMPTED_USERNAME";

    public AbstractUsernameFormAuthenticator() {
    }

    public void action(AuthenticationFlowContext context) {
    }

    protected Response challenge(AuthenticationFlowContext context, String error) {
        return this.challenge(context, error, (String)null);
    }

    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage (field, error));
            } else {
                form.setError(error, new Object[0]);
            }
        }
        return this.createLoginForm(form);
    }

    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsername();
    }

    protected String disabledByBruteForceError() {
        return "invalidUserMessage";
    }

    protected String disabledByBruteForceFieldError() {
        return "username";
    }

    protected Response setDuplicateUserChallenge(AuthenticationFlowContext context, String eventError, String loginFormError, AuthenticationFlowError authenticatorError) {
        context.getEvent().error(eventError);
        Response challengeResponse = context.form().setError(loginFormError, new Object[0]).createLoginUsernamePassword();
        context.failureChallenge(authenticatorError, challengeResponse);
        return challengeResponse;
    }

    protected void runDefaultDummyHash(AuthenticationFlowContext context) {
        PasswordHashProvider hash = (PasswordHashProvider)context.getSession().getProvider(PasswordHashProvider.class, "pbkdf2-sha256");
        hash.encode("SlightlyLongerDummyPassword", 27500);
    }

    protected void dummyHash(AuthenticationFlowContext context) {
        PasswordPolicy policy = context.getRealm().getPasswordPolicy();
        if (policy == null) {
            this.runDefaultDummyHash(context);
        } else {
            PasswordHashProvider hash = (PasswordHashProvider)context.getSession().getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
            if (hash == null) {
                this.runDefaultDummyHash(context);
            } else {
                hash.encode("SlightlyLongerDummyPassword", policy.getHashIterations());
            }
        }
    }

    public void testInvalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            this.dummyHash(context);
            context.getEvent().error("user_not_found");
            Response challengeResponse = this.challenge(context, this.getDefaultChallengeMessage(context), "username");
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
        }

    }

    public boolean enabledUser(AuthenticationFlowContext context, UserModel user) {
        if (this.isDisabledByBruteForce(context, user)) {
            return false;
        } else if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error("user_disabled");
            Response challengeResponse = this.challenge(context, "accountDisabledMessage");
            context.forceChallenge(challengeResponse);
            return false;
        } else {
            return true;
        }
    }

    public boolean validateUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        log.info ("--------------- Validating user ---------------");
        UserModel user = this.getUser(context, inputData);
        return user != null && this.validateUser(context, user, inputData);
    }

    private UserModel getUser(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        if (this.isUserAlreadySetBeforeUsernamePasswordAuth(context)) {
            UserModel user = context.getUser();
            this.testInvalidUser(context, user);
            return user;
        } else {
            context.clearUser();
            return this.getUserFromForm(context, inputData);
        }
    }

    private UserModel getUserFromForm(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        logger.info ("--------------- getUserFromForm -------------------");
        String username = (String)inputData.getFirst("username");
        if (username == null) {
            context.getEvent().error("user_not_found");
            Response challengeResponse = this.challenge(context, this.getDefaultChallengeMessage(context), "username");
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return null;
        } else {
            username = username.trim();
            context.getEvent().detail("username", username);
            context.getAuthenticationSession().setAuthNote("ATTEMPTED_USERNAME", username);
            UserModel user = null;

            try {
                user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
            } catch (ModelDuplicateException var6) {
                ServicesLogger.LOGGER.modelDuplicateException(var6);
                if (var6.getDuplicateFieldName() != null && var6.getDuplicateFieldName().equals("email")) {
                    this.setDuplicateUserChallenge(context, "email_in_use", "emailExistsMessage", AuthenticationFlowError.INVALID_USER);
                } else {
                    this.setDuplicateUserChallenge(context, "username_in_use", "usernameExistsMessage", AuthenticationFlowError.INVALID_USER);
                }

                return user;
            }

            this.testInvalidUser(context, user);
            return user;
        }
    }

    private boolean validateUser(AuthenticationFlowContext context, UserModel user, MultivaluedMap<String, String> inputData) {
        logger.info ("--------------- Validating user details -------------------");
        if (!this.enabledUser(context, user)) {
            return false;
        } else {
            String rememberMe = (String)inputData.getFirst("rememberMe");
            boolean remember = context.getRealm().isRememberMe() && rememberMe != null && rememberMe.equalsIgnoreCase("on");
            if (remember) {
                context.getAuthenticationSession().setAuthNote("remember_me", "true");
                context.getEvent().detail("remember_me", "true");
            } else {
                context.getAuthenticationSession().removeAuthNote("remember_me");
            }

            context.setUser(user);
            return true;
        }
    }


    protected boolean isDisabledByBruteForce(AuthenticationFlowContext context, UserModel user) {
        String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
        if (bruteForceError != null) {
            context.getEvent().user(user);
            context.getEvent().error(bruteForceError);
            Response challengeResponse = this.challenge(context, this.disabledByBruteForceError(), this.disabledByBruteForceFieldError());
            context.forceChallenge(challengeResponse);
            return true;
        } else {
            return false;
        }
    }

    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return this.isUserAlreadySetBeforeUsernamePasswordAuth(context) ? "invalidPasswordMessage" : "invalidUserMessage";
    }

    protected boolean isUserAlreadySetBeforeUsernamePasswordAuth(AuthenticationFlowContext context) {
        String userSet = context.getAuthenticationSession().getAuthNote("USER_SET_BEFORE_USERNAME_PASSWORD_AUTH");
        return Boolean.parseBoolean(userSet);
    }
}
