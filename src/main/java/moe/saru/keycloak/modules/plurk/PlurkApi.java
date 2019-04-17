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

import com.github.scribejava.core.builder.api.DefaultApi10a;

import com.github.scribejava.core.extractors.BaseStringExtractor;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.HttpClientConfig;
import java.io.OutputStream;

public class PlurkApi extends DefaultApi10a {

    private static final String AUTHORIZE_URL = "https://www.plurk.com/OAuth/authorize";
    private static final String REQUEST_TOKEN_RESOURCE = "www.plurk.com/OAuth/request_token";
    private static final String ACCESS_TOKEN_RESOURCE = "www.plurk.com/OAuth/access_token";

    protected PlurkApi() {
    }

    private static class InstanceHolder {
        private static final PlurkApi INSTANCE = new PlurkApi();
    }

    public static PlurkApi instance() {
        return InstanceHolder.INSTANCE;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return "https://" + ACCESS_TOKEN_RESOURCE;
    }

    @Override
    public String getRequestTokenEndpoint() {
        return "https://" + REQUEST_TOKEN_RESOURCE;
    }

    @Override
    public String getAuthorizationBaseUrl() {
        return AUTHORIZE_URL;
    }

    @Override
    public PlurkOAuth10aService createService(String apiKey, String apiSecret, String callback, String scope, OutputStream debugStream, String userAgent, HttpClientConfig httpClientConfig, HttpClient httpClient) {
        return new PlurkOAuth10aService(this, apiKey, apiSecret, callback, scope, debugStream, userAgent, httpClientConfig, httpClient);
    }

}
