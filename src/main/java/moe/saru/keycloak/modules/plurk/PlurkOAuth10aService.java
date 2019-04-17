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

import com.github.scribejava.core.oauth.OAuth10aService;

import java.io.IOException;
import java.util.concurrent.Future;
import org.jboss.logging.Logger;
import com.github.scribejava.core.builder.api.DefaultApi10a;
import com.github.scribejava.core.builder.api.OAuth1SignatureType;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.HttpClientConfig;
import com.github.scribejava.core.model.OAuth1AccessToken;
import com.github.scribejava.core.model.OAuth1RequestToken;
import com.github.scribejava.core.model.OAuthAsyncRequestCallback;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.ExecutionException;

/**
 * OAuth 1.0a implementation of {@link OAuthService}
 */
public class PlurkOAuth10aService extends OAuth10aService {

    protected static final Logger logger = Logger.getLogger(PlurkOAuth10aService.class);

    public PlurkOAuth10aService(DefaultApi10a api, String apiKey, String apiSecret, String callback, String scope, OutputStream debugStream, String userAgent, HttpClientConfig httpClientConfig, HttpClient httpClient) {
        super(api, apiKey, apiSecret, callback, scope, debugStream, userAgent, httpClientConfig, httpClient);
    }

    @Override
    protected OAuthRequest prepareRequestTokenRequest() {
        final OAuthRequest request = new OAuthRequest(getApi().getRequestTokenVerb(), getApi().getRequestTokenEndpoint());
        // we don't add callback param as it always make signature verification failed
        // instead, for plurk, it'll use configured in app console callback by default
        /*
        String callback = getCallback();
        if (callback == null) {
            callback = OAuthConstants.OOB;
        }
        log("setting oauth_callback to %s", callback);
        request.addOAuthParameter(OAuthConstants.CALLBACK, callback);
        */
        addOAuthParams(request, "");
        appendSignature(request);
        return request;
    }

    @Override
    public void log(String messagePattern, Object... params) {
        logger.debugf(messagePattern, params);
    }
}
