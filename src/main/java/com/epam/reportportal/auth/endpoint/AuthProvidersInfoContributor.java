/*
 * Copyright 2019 EPAM Systems
 *
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
package com.epam.reportportal.auth.endpoint;

import com.epam.reportportal.auth.oauth.OAuthProvider;
import com.epam.ta.reportportal.dao.OAuthRegistrationRepository;
import com.epam.ta.reportportal.dao.SamlProviderDetailsRepository;
import com.epam.ta.reportportal.entity.oauth.OAuthRegistration;
import com.epam.ta.reportportal.entity.saml.SamlProviderDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriUtils;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.epam.reportportal.auth.config.SecurityConfiguration.GlobalWebSecurityConfig.SSO_LOGIN_PATH;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

/**
 * Shows list of supported authentication providers
 *
 * @author <a href="mailto:andrei_varabyeu@epam.com">Andrei Varabyeu</a>
 */
@Component
public class AuthProvidersInfoContributor implements InfoContributor {

	private static final String SAML_BUTTON = "<span>Login with SAML</span>";

	private final OAuthRegistrationRepository oAuthRegistrationRepository;
	private final SamlProviderDetailsRepository samlProviderDetailsRepository;
	private final Map<String, OAuthProvider> providersMap;

	@Autowired
	public AuthProvidersInfoContributor(OAuthRegistrationRepository oAuthRegistrationRepository,
			SamlProviderDetailsRepository samlProviderDetailsRepository, Map<String, OAuthProvider> providersMap) {
		this.oAuthRegistrationRepository = oAuthRegistrationRepository;
		this.samlProviderDetailsRepository = samlProviderDetailsRepository;
		this.providersMap = providersMap;
	}

	@Override
	public void contribute(Info.Builder builder) {
		final List<OAuthRegistration> oauth2Details = oAuthRegistrationRepository.findAll();

		final Map<String, AuthProviderInfo> providers = providersMap.values()
				.stream()
				.filter(p -> !p.isConfigDynamic() || oauth2Details.stream().anyMatch(it -> it.getId().equalsIgnoreCase(p.getName())))
				.collect(Collectors.toMap(OAuthProvider::getName, p -> new OAuthProviderInfo(p.getButton(), p.buildPath(getAuthBasePath()))
				));

		Map<String, String> samlProviders = samlProviderDetailsRepository.findAll()
				.stream()
				.filter(SamlProviderDetails::isEnabled)
				.collect(Collectors.toMap(SamlProviderDetails::getIdpName,
						it -> fromCurrentContextPath().path(String.format("/saml/sp/discovery?idp=%s",
								UriUtils.encode(it.getIdpUrl(), UTF_8.toString())
						)).build().getPath()
				));

		if (!CollectionUtils.isEmpty(samlProviders)) {
			providers.put("samlProviders", new SamlProviderInfo(SAML_BUTTON, samlProviders));
		}

		builder.withDetail("authExtensions", providers);
	}

	private String getAuthBasePath() {
		return fromCurrentContextPath().path(SSO_LOGIN_PATH).build().getPath();
	}

	public abstract static class AuthProviderInfo {
		private String button;

		public AuthProviderInfo(String button) {
			this.button = button;
		}

		public String getButton() {
			return button;
		}

		public void setButton(String button) {
			this.button = button;
		}
	}

	public static class SamlProviderInfo extends AuthProviderInfo {
		private Map<String, String> providers;

		public SamlProviderInfo(String button, Map<String, String> providers) {
			super(button);
			this.providers = providers;
		}

		public Map<String, String> getProviders() {
			return providers;
		}

		public void setProviders(Map<String, String> providers) {
			this.providers = providers;
		}
	}

	public static class OAuthProviderInfo extends AuthProviderInfo {
		private String path;

		public OAuthProviderInfo(String button, String path) {
			super(button);
			this.path = path;
		}

		public String getPath() {
			return path;
		}

		public void setPath(String path) {
			this.path = path;
		}
	}

}
