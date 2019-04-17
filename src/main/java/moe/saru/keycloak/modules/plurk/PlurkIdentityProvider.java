/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package moe.saru.keycloak.modules.plurk;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.ExchangeTokenToIdentityProviderToken;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.github.scribejava.core.oauth.OAuth10aService;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth1AccessToken;
import com.github.scribejava.core.model.OAuth1RequestToken;
import com.github.scribejava.core.model.OAuthRequest;
//import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;

/**
 * @author dannyAAM
 */
public class PlurkIdentityProvider extends AbstractIdentityProvider<OAuth2IdentityProviderConfig> implements
        SocialIdentityProvider<OAuth2IdentityProviderConfig>, ExchangeTokenToIdentityProviderToken {

    String PLURK_TOKEN_TYPE="plurk";

    protected static final Logger logger = Logger.getLogger(PlurkIdentityProvider.class);

    private static final String PLURK_TOKEN = "plurk_token";
    private static final String PLURK_TOKENSECRET = "plurk_tokenSecret";
    private static final String PLURK_STATE = "plurk_state";

    public PlurkIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(realm, callback, event);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            OAuth10aService service = new ServiceBuilder(getConfig().getClientId())
                                        .apiSecret(getConfig().getClientSecret())
//                                        .callback(request.getRedirectUri())
                                        .build(PlurkApi.instance());

            OAuth1RequestToken requestToken = service.getRequestToken();
            AuthenticationSessionModel authSession = request.getAuthenticationSession();

            String encodedState = request.getState().getEncoded();
            logger.debugf("encodedState: %s", encodedState);

            authSession.setAuthNote(PLURK_TOKEN, requestToken.getToken());
            authSession.setAuthNote(PLURK_TOKENSECRET, requestToken.getTokenSecret());
            authSession.setAuthNote(PLURK_STATE, encodedState);

            URI authorizationUrl = URI.create(service.getAuthorizationUrl(requestToken));

            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could send authentication request to plurk.", e);
        }
    }

    @Override
    public Response exchangeFromToken(UriInfo uriInfo, EventBuilder builder, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject, MultivaluedMap<String, String> params) {
        String requestedType = params.getFirst(OAuth2Constants.REQUESTED_TOKEN_TYPE);
        if (requestedType != null && !requestedType.equals(PLURK_TOKEN_TYPE)) {
            return exchangeUnsupportedRequiredType();
        }
        if (!getConfig().isStoreToken()) {
            String brokerId = tokenUserSession.getNote(Details.IDENTITY_PROVIDER);
            if (brokerId == null || !brokerId.equals(getConfig().getAlias())) {
                return exchangeNotLinkedNoStore(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
            }
            return exchangeSessionToken(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        } else {
            return exchangeStoredToken(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
    }

    protected Response exchangeStoredToken(UriInfo uriInfo, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        FederatedIdentityModel model = session.users().getFederatedIdentity(tokenSubject, getConfig().getAlias(), authorizedClient.getRealm());
        if (model == null || model.getToken() == null) {
            return exchangeNotLinked(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        String accessToken = model.getToken();
        if (accessToken == null) {
            model.setToken(null);
            session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
            return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setToken(accessToken);
        tokenResponse.setIdToken(null);
        tokenResponse.setRefreshToken(null);
        tokenResponse.setRefreshExpiresIn(0);
        tokenResponse.getOtherClaims().clear();
        tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, PLURK_TOKEN_TYPE);
        tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
        return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    protected Response exchangeSessionToken(UriInfo uriInfo, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        String accessToken = tokenUserSession.getNote(IdentityProvider.FEDERATED_ACCESS_TOKEN);
        if (accessToken == null) {
            return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setToken(accessToken);
        tokenResponse.setIdToken(null);
        tokenResponse.setRefreshToken(null);
        tokenResponse.setRefreshExpiresIn(0);
        tokenResponse.getOtherClaims().clear();
        tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, PLURK_TOKEN_TYPE);
        tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
        return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
    }


    protected class Endpoint {
        protected RealmModel realm;
        protected AuthenticationCallback callback;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        @Context
        protected UriInfo uriInfo;



        private static final String apiUserdata = "https://www.plurk.com/APP/Users/me";

        public Endpoint(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
            this.realm = realm;
            this.callback = callback;
            this.event = event;
        }

        @GET
        public Response authResponse(@QueryParam("oauth_token") String oauthToken,
                                     @QueryParam("oauth_verifier") String verifier) {
            AuthenticationSessionModel authSession = null;
            try {
                OAuth10aService service = new ServiceBuilder(getConfig().getClientId())
                                            .apiSecret(getConfig().getClientSecret())
                                            .build(PlurkApi.instance());

                // find token secret by token in auth sessions
                AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
                authSession = asm.getCurrentRootAuthenticationSession(realm)
                    .getAuthenticationSessions().values().stream()
                    .filter(s -> oauthToken.equals(s.getAuthNote(PLURK_TOKEN)))
                    .findFirst().orElse(null);

                String plurkToken = authSession.getAuthNote(PLURK_TOKEN);
                String plurkSecret = authSession.getAuthNote(PLURK_TOKENSECRET);
                String encodedState = authSession.getAuthNote(PLURK_STATE);

                OAuth1RequestToken requestToken = new OAuth1RequestToken(plurkToken, plurkSecret);
                OAuth1AccessToken accessToken = service.getAccessToken(requestToken, verifier);

                OAuthRequest request = new OAuthRequest(Verb.GET, apiUserdata);
                service.signRequest(accessToken, request);
                com.github.scribejava.core.model.Response response = service.execute(request);

                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode profile = objectMapper.readTree(response.getBody());


                BrokeredIdentityContext identity = new BrokeredIdentityContext(getJsonProperty(profile, "id"));
                identity.setIdp(PlurkIdentityProvider.this);

                identity.setUsername(getJsonProperty(profile, "nick_name"));
                identity.setName(getJsonProperty(profile, "display_name"));

                StringBuilder tokenBuilder = new StringBuilder();

                tokenBuilder.append("{");
                tokenBuilder.append("\"oauth_token\":").append("\"").append(plurkToken).append("\"").append(",");
                tokenBuilder.append("\"oauth_token_secret\":").append("\"").append(plurkSecret).append("\"").append(",");
                tokenBuilder.append("\"nick_name\":").append("\"").append(getJsonProperty(profile, "nick_name")).append("\"").append(",");
                tokenBuilder.append("\"user_id\":").append("\"").append(getJsonProperty(profile, "id")).append("\"");
                tokenBuilder.append("}");
                String token = tokenBuilder.toString();
                if (getConfig().isStoreToken()) {
                    identity.setToken(token);
                }
                identity.getContextData().put(IdentityProvider.FEDERATED_ACCESS_TOKEN, token);

                identity.setIdpConfig(getConfig());
                identity.setCode(encodedState);

                return callback.authenticated(identity);
            } catch (WebApplicationException e) {
                sendErrorEvent();
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Couldn't get user profile from plurk.", e);
                sendErrorEvent();
                return ErrorPage.error(session, authSession, Response.Status.BAD_GATEWAY, Messages.UNEXPECTED_ERROR_HANDLING_RESPONSE);
            }
        }

        public String getJsonProperty(JsonNode jsonNode, String name) {
            if (jsonNode.has(name) && !jsonNode.get(name).isNull()) {
                String s = jsonNode.get(name).asText();
                if (s != null && !s.isEmpty())
                    return s;
                else
                    return null;
            }

            return null;
        }

        private void sendErrorEvent() {
            event.event(EventType.LOGIN);
            event.error("plurk_login_failed");
        }

    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.ok(identity.getToken()).type(MediaType.APPLICATION_JSON).build();
    }

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        authSession.setUserSessionNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, (String)context.getContextData().get(IdentityProvider.FEDERATED_ACCESS_TOKEN));

    }

}
