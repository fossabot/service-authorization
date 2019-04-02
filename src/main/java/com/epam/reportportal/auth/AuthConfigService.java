/*
 * Copyright 2016 EPAM Systems
 *
 *
 * This file is part of EPAM Report Portal.
 * https://github.com/reportportal/service-authorization
 *
 * Report Portal is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Report Portal is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Report Portal.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.epam.reportportal.auth;

import com.epam.reportportal.auth.store.MutableClientRegistrationRepository;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.InvocationTargetException;
import java.util.function.Function;

import static com.google.common.reflect.Reflection.newProxy;
import static java.util.Optional.ofNullable;

/**
 * Builds proxy instance of {@link RestTemplate} which load OAuth resouce detail s from DB on each operation
 *
 * @author <a href="mailto:andrei_varabyeu@epam.com">Andrei Varabyeu</a>
 */
@Component
public class AuthConfigService {

	@Autowired
	private MutableClientRegistrationRepository clientRegistrationRepository;

	/**
	 * Builds proxy instance of {@link RestTemplate} which load OAuth resouce details from DB on each operation
	 *
	 * @param name                Name/ID of resource of {@link RestTemplate}
	 * @param oauth2ClientContext OAuth Client context
	 * @return Proxy instance of {@link RestTemplate}
	 */
	public OAuth2RestOperations getRestTemplate(String name, OAuth2ClientContext oauth2ClientContext) {
		return newProxy(OAuth2RestOperations.class, (proxy, method, args) -> {
			try {
				return method.invoke(new OAuth2RestTemplate(loadResourceDetails(name), oauth2ClientContext), args);

			} catch (InvocationTargetException e) {
				throw e.getTargetException();
			}
		});
	}

	/**
	 * Loads {@link ClientRegistration} from database
	 *
	 * @param name Name of resource
	 * @return Built {@link OAuth2ProtectedResourceDetails}
	 */
	public ClientRegistration loadLoginDetails(String name) {
		return clientRegistrationRepository.findByRegistrationId(name);
	}

	/**
	 * Loads {@link OAuth2ProtectedResourceDetails} from database
	 *
	 * @param name Name of resource
	 * @return Built {@link OAuth2ProtectedResourceDetails}
	 */
	public OAuth2ProtectedResourceDetails loadResourceDetails(String name) {
		return RESOURCE_DETAILS_CONVERTER.apply(loadLoginDetails(name));
	}

	/**
	 * Converts DB model to {@link OAuth2ProtectedResourceDetails}
	 */
	private static final Function<ClientRegistration, OAuth2ProtectedResourceDetails> RESOURCE_DETAILS_CONVERTER = registration -> {
		BaseOAuth2ProtectedResourceDetails details;

		String grantType = registration.getAuthorizationGrantType().getValue();
		switch (grantType) {
			case "authorization_code":
				details = new AuthorizationCodeResourceDetails();
				break;
			case "implicit":
				details = new ImplicitResourceDetails();
				break;
			case "client_credentials":
				details = new ClientCredentialsResourceDetails();
				break;
			case "password":
				details = new ResourceOwnerPasswordResourceDetails();
				break;
			default:
				details = new BaseOAuth2ProtectedResourceDetails();
		}

		String authorizationUri = registration.getProviderDetails().getAuthorizationUri();
		if (null != authorizationUri) {
			((AbstractRedirectResourceDetails) details).setUserAuthorizationUri(authorizationUri);
		}

		details.setAccessTokenUri(registration.getProviderDetails().getTokenUri());

		String authorizationScheme = registration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod().getValue();
		if (null != authorizationScheme) {
			details.setAuthenticationScheme(AuthenticationScheme.valueOf(authorizationScheme));
		}

		details.setClientAuthenticationScheme(ofNullable(authorizationScheme).map(AuthenticationScheme::valueOf).orElse(null));

		details.setClientId(registration.getClientId());
		details.setClientSecret(registration.getClientSecret());

		if (null != registration.getScopes()) {
			details.setScope(Lists.newArrayList(registration.getScopes()));
		}
		return details;
	};
}
